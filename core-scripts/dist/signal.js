/**
 * LDP Signal Connector
 * Replicates Signal's custom key derivation and SQLCipher access.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import * as crypto from "node:crypto";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const SIGNAL_DB = path.join(os.homedir(), "Library/Application Support/Signal/sql/db.sqlite");
const SIGNAL_CONFIG = path.join(os.homedir(), "Library/Application Support/Signal/config.json");
export class SignalConnector {
    descriptor = {
        name: "signal",
        app: "Signal",
        version: "1.0",
        dataPaths: [SIGNAL_DB],
        permissions: ["messages.read", "contacts.read"],
        namedQueries: {
            conversations: "Recent conversations and message counts",
            messages: "Last 50 messages",
        },
        description: "Signal messenger data — secure local extraction.",
    };
    dbPath = undefined;
    key = undefined;
    async discover() {
        if (fs.existsSync(SIGNAL_DB)) {
            this.dbPath = SIGNAL_DB;
            return true;
        }
        return false;
    }
    async schema() {
        return {
            messages: {
                body: "message text",
                dateReceived: "timestamp",
                conversationId: "thread ID",
            },
            conversations: {
                name: "contact or group name",
                lastMessage: "preview text",
            },
        };
    }
    decryptKey() {
        const safePassword = execSync('security find-generic-password -s "Signal Safe Storage" -w', { encoding: "utf-8" }).trim();
        const config = JSON.parse(fs.readFileSync(SIGNAL_CONFIG, "utf-8"));
        const encryptedHex = config.encryptedKey;
        if (!encryptedHex)
            throw new Error("No encryptedKey in Signal config.json");
        const encBuf = Buffer.from(encryptedHex, "hex");
        const prefix = encBuf.toString("utf8", 0, 3);
        if (prefix !== "v10")
            throw new Error(`Unsupported prefix '${prefix}'`);
        const derivedKey = crypto.pbkdf2Sync(safePassword, "saltysalt", 1003, 16, "sha1");
        const iv = encBuf.subarray(3, 19);
        const ciphertext = encBuf.subarray(19);
        const decipher = crypto.createDecipheriv("aes-128-cbc", derivedKey, iv);
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString("utf8");
    }
    async read(query, limit = 500) {
        if (!this.dbPath)
            return [];
        // We need the Signal-specific SQLCipher build
        let Database;
        try {
            Database = require("@signalapp/sqlcipher");
        }
        catch {
            console.error("Signal connector requires @signalapp/sqlcipher. Skipping.");
            return [];
        }
        if (!this.key) {
            try {
                this.key = this.decryptKey();
            }
            catch (e) {
                console.error("Signal key extraction failed:", e);
                return [];
            }
        }
        const tmp = path.join(os.tmpdir(), `ldp_signal_${Date.now()}.db`);
        fs.copyFileSync(this.dbPath, tmp);
        // Copy WAL if exists
        if (fs.existsSync(this.dbPath + "-wal"))
            fs.copyFileSync(this.dbPath + "-wal", tmp + "-wal");
        try {
            const db = new Database(tmp);
            db.pragma(`key = "x'${this.key}'"`);
            const q = query.toLowerCase();
            let sql;
            if (q.includes("message")) {
                sql = `SELECT body, dateReceived, conversationId FROM messages WHERE body IS NOT NULL ORDER BY dateReceived DESC LIMIT ${limit}`;
            }
            else {
                sql = `SELECT * FROM conversations LIMIT ${limit}`;
            }
            const rows = db.prepare(sql).all();
            db.close();
            return rows;
        }
        catch (e) {
            console.error("Signal read error:", e);
            return [];
        }
        finally {
            try {
                fs.unlinkSync(tmp);
                fs.unlinkSync(tmp + "-wal");
            }
            catch { }
        }
    }
}
//# sourceMappingURL=signal.js.map