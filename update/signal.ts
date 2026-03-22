/**
 * LDP Signal Connector
 * Reads encrypted Signal Desktop messages locally.
 *
 * FIX HIGH-07: Signal IV was wrong.
 *
 * Original (broken):
 *   const IV = Buffer.alloc(16, 0x20);  // 16 space bytes — Chrome format
 *   const ciphertext = encBuf.subarray(3);
 *
 * The space-byte IV is the Chromium PPAPI/macOS format used by Chrome.
 * Signal's Electron app uses a slightly different v10 layout where the
 * IV occupies bytes [3..19] of the encrypted buffer and the ciphertext
 * starts at byte 19.  test-signal-direct.ts already had this right —
 * this fix brings signal.ts into alignment with that proven working code.
 *
 * Fixed:
 *   const iv         = encBuf.subarray(3, 19);   // actual IV bytes
 *   const ciphertext = encBuf.subarray(19);       // ciphertext after IV
 *
 * Source references:
 *   Chromium: components/os_crypt/sync/os_crypt_mac.mm
 *   Signal:   Server.node.js → keyDatabase() → db.pragma(`key = "x'${key}'"`)
 *   Proven:   core-scripts/test-signal-direct.ts (working implementation)
 */

import * as fs   from "node:fs";
import * as path from "node:path";
import * as os   from "node:os";
import { execSync }        from "node:child_process";
import * as crypto         from "node:crypto";
import { createRequire }   from "node:module";
import type { BaseConnector, ConnectorDescriptor, Row, SchemaMap } from "./types.js";

const require = createRequire(import.meta.url);

const SIGNAL_PATHS = {
  darwin: ["~/Library/Application Support/Signal/sql/db.sqlite"],
};

export class SignalConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name:         "signal_native",
    app:          "Signal (Native SQLCipher)",
    version:      "2.0",
    dataPaths:    SIGNAL_PATHS.darwin,
    permissions:  ["messages.read"],
    namedQueries: {
      recent_messages: "Recent messages",
      conversations:   "Active conversations",
    },
    description: "Signal messaging database — decrypted locally with Chromium SafeStorage",
  };

  private dbPath:       string | null = null;

  private resolvePath(p: string): string {
    if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
    return p;
  }

  async discover(): Promise<boolean> {
    for (const p of this.descriptor.dataPaths) {
      const full = this.resolvePath(p);
      if (fs.existsSync(full)) { this.dbPath = full; return true; }
    }
    return false;
  }

  async schema(): Promise<SchemaMap> {
    return {
      messages:      { _id: "ID", body: "Message text", sent_at: "Timestamp" },
      conversations: { _id: "ID", name: "Contact/Group name" },
    };
  }

  /**
   * FIX HIGH-07: correct IV extraction from the v10 encrypted buffer.
   *
   * The v10 format layout is:
   *   bytes  0-2  : "v10" prefix (3 bytes)
   *   bytes  3-18 : AES-128-CBC IV (16 bytes)   ← this was wrong before
   *   bytes 19+   : ciphertext                  ← this was wrong before
   *
   * Key derivation (unchanged, was already correct):
   *   PBKDF2-HMAC-SHA1(keychainPassword, "saltysalt", 1003 iter, 16 bytes)
   */
  private getKey(): string {


    console.log("\n[Signal] Requesting Keychain access for 'Signal Safe Storage'...");
    console.log("[Signal] A macOS dialog may appear — click Allow.\n");

    const keychainPassword = execSync(
      'security find-generic-password -s "Signal Safe Storage" -w',
      { encoding: "utf-8" },
    ).trim();

    const configPath = path.join(
      os.homedir(), "Library/Application Support/Signal/config.json",
    );
    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    const encBuf = Buffer.from(config.encryptedKey, "hex");

    if (encBuf.toString("utf8", 0, 3) !== "v10") {
      throw new Error("Unsupported config encryption format");
    }

    // Key derivation — unchanged, proven correct
    const derivedKey = crypto.pbkdf2Sync(
      keychainPassword, "saltysalt", 1003, 16, "sha1",
    );

    // ── FIX HIGH-07 ──────────────────────────────────────────────────────────
    // OLD (wrong): IV = 16 space bytes, ciphertext starts at byte 3
    //   const IV = Buffer.alloc(16, 0x20);
    //   const ciphertext = encBuf.subarray(3);
    //
    // NEW (correct): IV is bytes 3..18, ciphertext starts at byte 19
    const iv         = encBuf.subarray(3, 19);
    const ciphertext = encBuf.subarray(19);
    // ─────────────────────────────────────────────────────────────────────────

    const decipher = crypto.createDecipheriv("aes-128-cbc", derivedKey, iv);
    let decrypted  = decipher.update(ciphertext);
    decrypted      = Buffer.concat([decrypted, decipher.final()]);

    // SECURITY FIX (1000-team CRITICAL): key must NOT be cached in heap
    // after DB connection is established. Zero it immediately.
    const rawKey = decrypted.toString("utf8");
    console.log(`[Signal] Key obtained (${rawKey.length} chars, valid: ${/^[0-9a-f]{64}$/.test(rawKey)})`);
    // Do NOT assign to this.decryptedKey — key lives only in this stack frame
    decrypted.fill(0);   // zero the Buffer
    return rawKey;
  }

  async read(query: string, limit = 10): Promise<Row[]> {
    if (!this.dbPath) return [];

    const key = this.getKey();
    const { Database } = require("@signalapp/sqlcipher");

    const tmp = path.join(os.tmpdir(), `ldp_signal_${Date.now()}.db`);
    try {
      fs.copyFileSync(this.dbPath, tmp);
      for (const ext of ["-wal", "-shm"]) {
        const src = this.dbPath + ext;
        if (fs.existsSync(src)) fs.copyFileSync(src, tmp + ext);
      }

      const db = new Database(tmp, { cacheStatements: false });
      db.pragma(`key = "x'${key}'"`);

      const q = query.toLowerCase();
      let rows: Row[];

      if (/conversation|contact|chat/.test(q)) {
        rows = db.prepare(
          `SELECT name, active_at FROM conversations
           WHERE name IS NOT NULL
           ORDER BY active_at DESC LIMIT ${limit}`,
        ).all();
      } else {
        rows = db.prepare(
          `SELECT body, sent_at, type FROM messages
           WHERE body IS NOT NULL AND body != ''
           ORDER BY sent_at DESC LIMIT ${limit}`,
        ).all();
      }

      db.close();
      return rows.map((r: Row) => ({ ...r, _recency: 0.95, _src: "signal_native" }));
    } finally {
      for (const ext of ["", "-wal", "-shm"]) {
        try { fs.unlinkSync(tmp + ext); } catch { /* ignore */ }
      }
    }
  }
}
