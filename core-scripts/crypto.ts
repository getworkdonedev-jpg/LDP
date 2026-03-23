/**
 * LDP Crypto — AES-256-GCM
 * Key derived from machine ID via PBKDF2. Never stored in plaintext.
 * All LDP data at rest is encrypted through this module.
 *
 * FIX CRITICAL-03: hashDescriptor now uses deepSort() for fully
 * deterministic canonical JSON across all Node.js versions.
 */

import * as crypto from "node:crypto";
import * as fs     from "node:fs";
import * as os     from "node:os";
import * as path   from "node:path";

export const LDP_DIR = path.join(os.homedir(), ".ldp");
const SALT_FILE       = path.join(LDP_DIR, ".salt");
const KEY_ITERATIONS  = 480_000;
const KEY_LEN         = 32; // 256 bits

function machineId(): Buffer {
  try {
    if (process.platform === "linux") {
      return Buffer.from(fs.readFileSync("/etc/machine-id", "utf8").trim());
    }
    if (process.platform === "darwin") {
      try {
        const { execSync } = require("child_process");
        const out   = execSync("ioreg -rd1 -c IOPlatformExpertDevice", { encoding: "utf8" });
        const match = out.match(/IOPlatformUUID[^=]+=\s*"([^"]+)"/);
        if (match) return Buffer.from(match[1]);
      } catch { /* fallback */ }
    }
  } catch { /* fallback */ }
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

function getOrCreateSalt(): Buffer {
  fs.mkdirSync(LDP_DIR, { recursive: true, mode: 0o700 });
  if (fs.existsSync(SALT_FILE)) {
    return Buffer.from(fs.readFileSync(SALT_FILE, "utf8").trim(), "base64");
  }
  const salt = crypto.randomBytes(32);
  fs.writeFileSync(SALT_FILE, salt.toString("base64"), { mode: 0o600 });
  return salt;
}

function deriveKey(salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(machineId(), salt, KEY_ITERATIONS, KEY_LEN, "sha256");
}

export class LDPCrypto {
  private readonly key: Buffer;

  constructor() {
    fs.mkdirSync(LDP_DIR, { recursive: true, mode: 0o700 });
    this.key = deriveKey(getOrCreateSalt());
  }

  /** Encrypt a string → base64 ciphertext (nonce + auth tag + ciphertext). */
  encrypt(data: string): string {
    const nonce  = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, nonce);
    const ct     = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
    const tag    = cipher.getAuthTag();
    return Buffer.concat([nonce, tag, ct]).toString("base64");
  }

  /** Decrypt base64 ciphertext. Throws if tampered. */
  decrypt(blob: string): string {
    const raw      = Buffer.from(blob, "base64");
    const nonce    = raw.subarray(0, 12);
    const tag      = raw.subarray(12, 28);
    const ct       = raw.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  }

  encryptJson(obj: unknown): string       { return this.encrypt(JSON.stringify(obj)); }
  decryptJson<T = unknown>(blob: string): T { return JSON.parse(this.decrypt(blob)) as T; }

  writeEncrypted(filePath: string, obj: unknown): void {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmpPath = `${filePath}.${crypto.randomBytes(4).toString("hex")}.tmp`;
    const data = this.encryptJson(obj);
    fs.writeFileSync(tmpPath, data, { mode: 0o600 });
    fs.renameSync(tmpPath, filePath);
  }

  readEncrypted<T = Record<string, unknown>>(filePath: string): T {
    if (!fs.existsSync(filePath)) return {} as T;
    try { return this.decryptJson<T>(fs.readFileSync(filePath, "utf8")); }
    catch { return {} as T; }
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
  hashDescriptor(obj: object): string {
    const canonical = JSON.stringify(deepSort(obj));
    return crypto.createHash("sha256").update(canonical).digest("hex").slice(0, 16);
  }
}

/**
 * Recursively sort all object keys alphabetically.
 * Arrays preserve order (order is meaningful in arrays).
 * Primitives pass through unchanged.
 */
function deepSort(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(deepSort);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as object).sort()) {
      sorted[key] = deepSort((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

let _instance: LDPCrypto | null = null;
export function getCrypto(): LDPCrypto {
  return (_instance ??= new LDPCrypto());
}
