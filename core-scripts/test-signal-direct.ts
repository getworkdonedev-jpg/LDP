/**
 * Signal Connector — uses Signal's own @signalapp/sqlcipher fork.
 * Key extraction uses the macOS Keychain via `security` CLI to get
 * the "Signal Safe Storage" password, then derives from it using
 * the Chromium v10 AES-128-CBC scheme.
 *
 * IMPORTANT: This is Signal's exact key flow per their open-source code:
 *   main.main.js → safeStorage.decryptString(Buffer.from(encryptedKey, "hex"))
 *   Server.node.js → db.pragma(`key = "x'${key}'"`)
 *
 * Since we can't call Electron's safeStorage, we replicate it with the
 * raw Chromium key derivation (pbkdf2/saltysalt/v10) from the Keychain.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import * as crypto from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// Use Signal's own SQLCipher fork — exact same native module they ship
const Database = require("@signalapp/sqlcipher");

// ── Path resolution ────────────────────────────────────────────────────────────

const SIGNAL_DB = path.join(
  os.homedir(),
  "Library/Application Support/Signal/sql/db.sqlite"
);

const SIGNAL_CONFIG = path.join(
  os.homedir(),
  "Library/Application Support/Signal/config.json"
);

// ── Key decryption (Chromium v10 protocol) ────────────────────────────────────

function decryptSignalKey(): string {
  console.log(
    "\n[Signal] Requesting Keychain access for 'Signal Safe Storage'..."
  );
  console.log(
    "[Signal] If a dialog appears, click Allow.\n"
  );

  // Step 1 – get the raw safe-storage password from the Keychain
  const safePassword = execSync(
    'security find-generic-password -s "Signal Safe Storage" -w',
    { encoding: "utf-8" }
  ).trim();

  // Step 2 – read the encrypted key from config.json
  const config = JSON.parse(fs.readFileSync(SIGNAL_CONFIG, "utf-8"));
  const encryptedHex: string = config.encryptedKey;
  if (!encryptedHex) throw new Error("No encryptedKey in Signal config.json");

  const encBuf = Buffer.from(encryptedHex, "hex");

  // Step 3 – verify and strip the v10 prefix
  const prefix = encBuf.toString("utf8", 0, 3);
  if (prefix !== "v10") {
    throw new Error(`Unsupported prefix '${prefix}'; expected 'v10'`);
  }

  // Step 4 – derive 16-byte AES key from the Keychain password
  const derivedKey = crypto.pbkdf2Sync(safePassword, "saltysalt", 1003, 16, "sha1");

  // Step 5 – AES-128-CBC decrypt (IV = bytes 3..19, ciphertext = bytes 19..)
  const iv = encBuf.subarray(3, 19);
  const ciphertext = encBuf.subarray(19);
  const decipher = crypto.createDecipheriv("aes-128-cbc", derivedKey, iv);
  let decrypted = decipher.update(ciphertext);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  // The result is the raw database key (Signal's source shows it's a hex string)
  const key = decrypted.toString("utf8");
  console.log(`[Signal] Decrypted key length: ${key.length} chars`);
  console.log(`[Signal] Is 64-char hex? ${/^[0-9a-f]{64}$/i.test(key)}`);
  return key;
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  if (!fs.existsSync(SIGNAL_DB)) {
    console.error("Signal database not found:", SIGNAL_DB);
    process.exit(1);
  }

  let key: string;
  try {
    key = decryptSignalKey();
  } catch (e) {
    console.error("Key extraction failed:", e);
    process.exit(1);
  }

  // Copy the database to avoid WAL locking issues
  const tmp = path.join(os.tmpdir(), `ldp_signal_${Date.now()}.db`);
  fs.copyFileSync(SIGNAL_DB, tmp);

  // Copy WAL/SHM files too if they exist (needed for a consistent snapshot)
  for (const ext of ["-wal", "-shm"]) {
    const src = SIGNAL_DB + ext;
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, tmp + ext);
    }
  }

  try {
    // Open using @signalapp/sqlcipher — Signal's own synchronous better-sqlite3 fork
    const db = new Database(tmp, { cacheStatements: true });

    // Exact same PRAGMA from Signal's Server.node.js keyDatabase()
    db.pragma(`key = "x'${key}'"`);
    db.pragma("journal_mode = WAL");

    // Quick sanity check
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).all();
    console.log("\n[Signal] Tables found:", tables.map((r: any) => r.name).join(", "));

    // Fetch recent messages
    const messages = db.prepare(
      `SELECT _id, body, dateReceived, conversationId
       FROM messages
       WHERE body IS NOT NULL AND body != ''
       ORDER BY dateReceived DESC
       LIMIT 10`
    ).all();

    console.log(`\n[Signal] 🎉 SUCCESS — ${messages.length} recent messages:\n`);
    for (const msg of messages as any[]) {
      const date = new Date(msg.dateReceived).toLocaleString();
      const body = (msg.body as string).substring(0, 80);
      console.log(`  [${date}] ${body}`);
    }

    db.close();
  } catch (e) {
    console.error("\n[Signal] DB error:", e);
  } finally {
    // Clean up temp copies
    for (const ext of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(tmp + ext); } catch {}
    }
  }
}

main();
