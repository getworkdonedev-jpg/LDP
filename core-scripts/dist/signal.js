/**
 * Signal Connector — reads encrypted Signal Desktop messages locally.
 *
 * Key decryption algorithm (Chromium macOS SafeStorage / v10 format):
 *   1. Fetch the AES password from macOS Keychain: 'Signal Safe Storage'
 *   2. Derive 16-byte AES key via PBKDF2-HMAC-SHA1(password, "saltysalt", 1003)
 *   3. Decrypt config.json encryptedKey using AES-128-CBC with IV = 16 spaces
 *   4. Open db.sqlite using Signal's @signalapp/sqlcipher fork
 *   5. Apply: PRAGMA key = "x'<64-char-hex-key>'"
 *
 * Source references:
 *   Chromium: components/os_crypt/sync/os_crypt_mac.mm (kIv = 16 spaces, kIterations = 1003)
 *   Signal:   Server.node.js → keyDatabase() → db.pragma(`key = "x'${key}'"`)
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import * as crypto from "node:crypto";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const SIGNAL_PATHS = {
    darwin: ["~/Library/Application Support/Signal/sql/db.sqlite"],
};
export class SignalConnector {
    descriptor = {
        name: "signal_native",
        app: "Signal (Native SQLCipher)",
        version: "2.0",
        dataPaths: SIGNAL_PATHS.darwin,
        permissions: ["messages.read"],
        namedQueries: {
            recent_messages: "Recent messages",
            conversations: "Active conversations",
        },
        description: "Signal messaging database — decrypted locally with Chromium SafeStorage",
    };
    dbPath = null;
    decryptedKey = null;
    resolvePath(p) {
        if (p.startsWith("~/"))
            return path.join(os.homedir(), p.slice(2));
        return p;
    }
    async discover() {
        for (const p of this.descriptor.dataPaths) {
            const full = this.resolvePath(p);
            if (fs.existsSync(full)) {
                this.dbPath = full;
                return true;
            }
        }
        return false;
    }
    async schema() {
        return {
            messages: { _id: "ID", body: "Message text", sent_at: "Timestamp" },
            conversations: { _id: "ID", name: "Contact/Group name" },
        };
    }
    /**
     * Decrypts the Signal database key using the correct Chromium macOS SafeStorage scheme:
     *   AES-128-CBC, IV = 16 space bytes, key = PBKDF2(keychainPassword, "saltysalt", 1003, 16, sha1)
     */
    getKey() {
        if (this.decryptedKey)
            return this.decryptedKey;
        console.log("\n[Signal] Requesting Keychain access for 'Signal Safe Storage'...");
        console.log("[Signal] A macOS dialog may appear — click Allow.\n");
        const keychainPassword = execSync('security find-generic-password -s "Signal Safe Storage" -w', { encoding: "utf-8" }).trim();
        const configPath = path.join(os.homedir(), "Library/Application Support/Signal/config.json");
        const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
        const encBuf = Buffer.from(config.encryptedKey, "hex");
        if (encBuf.toString("utf8", 0, 3) !== "v10") {
            throw new Error("Unsupported config encryption format");
        }
        // Chromium macOS: PBKDF2(password, "saltysalt", 1003 iterations, 16 bytes, SHA-1)
        const derivedKey = crypto.pbkdf2Sync(keychainPassword, "saltysalt", 1003, 16, "sha1");
        // Fixed IV of 16 space characters (0x20) — from Chromium source os_crypt_mac.mm
        const IV = Buffer.alloc(16, 0x20);
        // Ciphertext starts at byte 3 (after "v10" prefix)
        const ciphertext = encBuf.subarray(3);
        const decipher = crypto.createDecipheriv("aes-128-cbc", derivedKey, IV);
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        this.decryptedKey = decrypted.toString("utf8");
        console.log(`[Signal] Key obtained (${this.decryptedKey.length} chars, valid: ${/^[0-9a-f]{64}$/.test(this.decryptedKey)})`);
        return this.decryptedKey;
    }
    async read(query, limit = 10) {
        if (!this.dbPath)
            return [];
        const key = this.getKey();
        // Use Signal's own @signalapp/sqlcipher fork — same native module they ship
        const { Database } = require("@signalapp/sqlcipher");
        const tmp = path.join(os.tmpdir(), `ldp_signal_${Date.now()}.db`);
        try {
            fs.copyFileSync(this.dbPath, tmp);
            for (const ext of ["-wal", "-shm"]) {
                const src = this.dbPath + ext;
                if (fs.existsSync(src))
                    fs.copyFileSync(src, tmp + ext);
            }
            const db = new Database(tmp, { cacheStatements: false });
            // Signal's exact PRAGMA from Server.node.js → keyDatabase()
            db.pragma(`key = "x'${key}'"`);
            const q = query.toLowerCase();
            let rows;
            if (/conversation|contact|chat/.test(q)) {
                rows = db.prepare(`SELECT name, active_at FROM conversations WHERE name IS NOT NULL ORDER BY active_at DESC LIMIT ${limit}`).all();
            }
            else {
                rows = db.prepare(`SELECT body, sent_at, type FROM messages
           WHERE body IS NOT NULL AND body != ''
           ORDER BY sent_at DESC LIMIT ${limit}`).all();
            }
            db.close();
            return rows.map((r) => ({ ...r, _recency: 0.95, _src: "signal_native" }));
        }
        finally {
            for (const ext of ["", "-wal", "-shm"]) {
                try {
                    fs.unlinkSync(tmp + ext);
                }
                catch { }
            }
        }
    }
}
