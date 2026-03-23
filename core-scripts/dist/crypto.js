/**
 * LDP Crypto — AES-256-GCM
 * Key derived from machine ID via PBKDF2. Never stored in plaintext.
 * All LDP data at rest is encrypted through this module.
 *
 * FIX CRITICAL-03: hashDescriptor now uses deepSort() for fully
 * deterministic canonical JSON across all Node.js versions.
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
export const LDP_DIR = path.join(os.homedir(), ".ldp");
const SALT_FILE = path.join(LDP_DIR, ".salt");
const KEY_ITERATIONS = 480_000;
const KEY_LEN = 32; // 256 bits
function machineId() {
    try {
        if (process.platform === "linux") {
            return Buffer.from(fs.readFileSync("/etc/machine-id", "utf8").trim());
        }
        if (process.platform === "darwin") {
            try {
                const { execSync } = require("child_process");
                const out = execSync("ioreg -rd1 -c IOPlatformExpertDevice", { encoding: "utf8" });
                const match = out.match(/IOPlatformUUID[^=]+=\s*"([^"]+)"/);
                if (match)
                    return Buffer.from(match[1]);
            }
            catch { /* fallback */ }
        }
    }
    catch { /* fallback */ }
    const ifaces = os.networkInterfaces();
    for (const list of Object.values(ifaces)) {
        for (const addr of list ?? []) {
            if (!addr.internal && addr.mac !== "00:00:00:00:00:00") {
                return Buffer.from(addr.mac.replace(/:/g, ""));
            }
        }
    }
    return Buffer.from("ldp-fallback-id");
}
function getOrCreateSalt() {
    fs.mkdirSync(LDP_DIR, { recursive: true, mode: 0o700 });
    if (fs.existsSync(SALT_FILE)) {
        return Buffer.from(fs.readFileSync(SALT_FILE, "utf8").trim(), "base64");
    }
    const salt = crypto.randomBytes(32);
    fs.writeFileSync(SALT_FILE, salt.toString("base64"), { mode: 0o600 });
    return salt;
}
function deriveKey(salt) {
    return crypto.pbkdf2Sync(machineId(), salt, KEY_ITERATIONS, KEY_LEN, "sha256");
}
export class LDPCrypto {
    key;
    constructor() {
        fs.mkdirSync(LDP_DIR, { recursive: true, mode: 0o700 });
        this.key = deriveKey(getOrCreateSalt());
    }
    /** Encrypt a string → base64 ciphertext (nonce + auth tag + ciphertext). */
    encrypt(data) {
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", this.key, nonce);
        const ct = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([nonce, tag, ct]).toString("base64");
    }
    /** Decrypt base64 ciphertext. Throws if tampered. */
    decrypt(blob) {
        const raw = Buffer.from(blob, "base64");
        const nonce = raw.subarray(0, 12);
        const tag = raw.subarray(12, 28);
        const ct = raw.subarray(28);
        const decipher = crypto.createDecipheriv("aes-256-gcm", this.key, nonce);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
    }
    encryptJson(obj) { return this.encrypt(JSON.stringify(obj)); }
    decryptJson(blob) { return JSON.parse(this.decrypt(blob)); }
    writeEncrypted(filePath, obj) {
        const dir = path.dirname(filePath);
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        const tmpPath = `${filePath}.${crypto.randomBytes(4).toString("hex")}.tmp`;
        const data = this.encryptJson(obj);
        fs.writeFileSync(tmpPath, data, { mode: 0o600 });
        fs.renameSync(tmpPath, filePath);
    }
    readEncrypted(filePath) {
        if (!fs.existsSync(filePath))
            return {};
        try {
            return this.decryptJson(fs.readFileSync(filePath, "utf8"));
        }
        catch {
            return {};
        }
    }
    /**
     * SHA-256 fingerprint of a connector descriptor.
     *
     * FIX CRITICAL-03: original used Object.keys(obj).sort() which only
     * sorted top-level keys. Nested objects retained insertion order,
     * making fingerprints non-deterministic across Node versions.
     *
     * Fix: deepSort() recursively sorts all object keys before
     * JSON.stringify(), guaranteeing identical output regardless of
     * key insertion order at any nesting depth.
     */
    hashDescriptor(obj) {
        const canonical = JSON.stringify(deepSort(obj));
        return crypto.createHash("sha256").update(canonical).digest("hex").slice(0, 16);
    }
}
/**
 * Recursively sort all object keys alphabetically.
 * Arrays preserve order (order is meaningful in arrays).
 * Primitives pass through unchanged.
 */
function deepSort(value) {
    if (Array.isArray(value)) {
        return value.map(deepSort);
    }
    if (value !== null && typeof value === "object") {
        const sorted = {};
        for (const key of Object.keys(value).sort()) {
            sorted[key] = deepSort(value[key]);
        }
        return sorted;
    }
    return value;
}
let _instance = null;
export function getCrypto() {
    return (_instance ??= new LDPCrypto());
}
//# sourceMappingURL=crypto.js.map