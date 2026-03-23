/**
 * LDP Self-Learning Brain
 * =======================
 * Makes Signal-style manual debugging obsolete.
 *
 * 1. APPROVAL MANAGER  — one dialog per category, remembered forever
 * 2. ERROR BRAIN       — understands WHY a failure happened
 * 3. EXPERIMENT ENGINE — tries every decryption method autonomously
 * 4. KNOWLEDGE BASE    — stores every solved problem permanently
 */

import * as fs           from "node:fs";
import * as path         from "node:path";
import * as os           from "node:os";
import * as crypto       from "node:crypto";
import { execSync }      from "node:child_process";
import { createRequire } from "node:module";
import { getCrypto, LDP_DIR } from "./crypto.js";

const require = createRequire(import.meta.url);

// ── Paths ────────────────────────────────────────────────────────────────────
const APPROVALS_FILE = path.join(LDP_DIR, "approvals.json");
const KNOWLEDGE_FILE = path.join(LDP_DIR, "brain_knowledge.json");

// ── Types ────────────────────────────────────────────────────────────────────
export type DataCategory =
  | "messaging" | "browser" | "developer" | "health"
  | "finance"   | "notes"   | "media"     | "contacts"
  | "calendar"  | "other";

export type DecryptMethod =
  | "plain_sqlite"
  | "sqlcipher_chromium_safestore"
  | "sqlcipher_pbkdf2_spaces_iv"
  | "sqlcipher_pbkdf2_embedded_iv"
  | "sqlcipher_direct_hex"
  | "sqlcipher_v3_compat"
  | "unknown";

export interface KnownSolution {
  appKey:       string;
  appName:      string;
  filePath:     string;
  method:       DecryptMethod;
  category:     DataCategory;
  params:       Record<string, unknown>;
  schema:       Record<string, string[]>;
  confidence:   number;
  totalRows?:   number;
  maxRows?:     number;
  solvedAt:     number;
  solvedOnOS:   string;
  successCount: number;
  failureCount: number;
}

interface DecryptResult {
  success:   boolean;
  key?:      string;
  error?:    string;
  rowCount?: number;
}

interface DecryptStrategy {
  method:      DecryptMethod;
  description: string;
  rank:        number;
  tryFn:       (filePath: string, appName: string) => Promise<DecryptResult>;
}

export type BrainErrorType =
  | "decrypt_failed" | "file_locked" | "permission_denied"
  | "schema_changed" | "file_not_found" | "unknown";

export interface StaticApp {
  name:            string;
  pathPattern:     string;
  category:        DataCategory;
  strategy:        DecryptMethod;
  requiresConsent: boolean;
  autoRegister:    boolean;
  params:          Record<string, unknown>;
}

export interface BrainDiagnosis {
  errorType:   BrainErrorType;
  appName:     string;
  filePath:    string;
  suggestion:  string;
  recoverable: boolean;
  retryWith?:  DecryptMethod;
}

export interface BrainOptions {
  apiKey?:  string;
  verbose?: boolean;
}

// ── Category metadata ─────────────────────────────────────────────────────────
const CATEGORY_APPS: Record<DataCategory, string[]> = {
  messaging:  ["Signal", "iMessage", "WhatsApp", "Telegram", "Slack", "Discord"],
  browser:    ["Chrome", "Firefox", "Safari", "Brave", "Chromium"],
  developer:  ["VS Code", "Cursor", "git", "shell history"],
  health:     ["Apple Health", "fitness apps"],
  finance:    ["banking exports", "transaction files"],
  notes:      ["Apple Notes", "Obsidian", "Notion", "Bear"],
  media:      ["Spotify", "Apple Music"],
  contacts:   ["Apple Contacts"],
  calendar:   ["Apple Calendar", "Reminders"],
  other:      ["unknown apps"],
};

const CATEGORY_DESC: Record<DataCategory, string> = {
  messaging:  "Private messages — Signal, iMessage, WhatsApp, Telegram and others",
  browser:    "Browsing history — sites visited, search queries, bookmarks",
  developer:  "Coding activity — VS Code files, git commits, shell commands",
  health:     "Health and fitness data — steps, heart rate, workouts",
  finance:    "Financial data — transactions, account statements",
  notes:      "Notes and documents — Apple Notes, Obsidian, Notion",
  media:      "Media history — Spotify listening, play counts",
  contacts:   "Contacts — names, phone numbers, email addresses",
  calendar:   "Calendar events and reminders",
  other:      "Other local app databases found on this machine",
};

// ── Approval Manager ──────────────────────────────────────────────────────────
interface ApprovalRecord { category: DataCategory; grantedAt: number; grantedBy: string; }

export class ApprovalManager {
  private store = new Map<DataCategory, ApprovalRecord>();
  private readonly cry = getCrypto();

  constructor() { this.load(); }

  private load() {
    try {
      const raw = this.cry.readEncrypted<Record<string, ApprovalRecord>>(APPROVALS_FILE);
      for (const [c, r] of Object.entries(raw)) this.store.set(c as DataCategory, r);
    } catch {}
  }

  private save() {
    const obj: Record<string, ApprovalRecord> = {};
    for (const [c, r] of this.store) obj[c] = r;
    this.cry.writeEncrypted(APPROVALS_FILE, obj);
  }

  isApproved(category: DataCategory): boolean { return this.store.has(category); }

  grant(category: DataCategory, grantedBy = "user") {
    this.store.set(category, { category, grantedAt: Date.now() / 1000, grantedBy });
    this.save();
  }

  revoke(category: DataCategory) { this.store.delete(category); this.save(); }
  listApproved(): DataCategory[] { return [...this.store.keys()]; }

  async request(
    category: DataCategory,
    appName:  string,
    promptFn?: (msg: string) => Promise<boolean>,
  ): Promise<boolean> {
    if (this.isApproved(category)) return true;

    const apps = CATEGORY_APPS[category].join(", ");
    const msg =
      `\n┌─────────────────────────────────────────────────────┐\n` +
      `│  LDP — Data Access Request                          │\n` +
      `└─────────────────────────────────────────────────────┘\n\n` +
      `  App found:  ${appName}\n` +
      `  Category:   ${category}\n\n` +
      `  ${CATEGORY_DESC[category]}.\n\n` +
      `  Includes: ${apps}\n\n` +
      `  Approving grants access to ALL apps in this\n` +
      `  category. Your data never leaves this device.\n\n` +
      `  Approve "${category}" access? [yes/no]: `;

    const fn = promptFn ?? defaultCLIPrompt;
    const ok = await fn(msg);
    if (ok) {
      this.grant(category);
      console.log(`[BRAIN] ✓ "${category}" approved — ${CATEGORY_APPS[category].length} apps will connect silently.`);
    } else {
      console.log(`[BRAIN] ✗ "${category}" denied.`);
    }
    return ok;
  }
}

async function defaultCLIPrompt(msg: string): Promise<boolean> {
  process.stdout.write(msg);
  return new Promise(res => {
    let buf = "";
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => {
      buf += chunk;
      if (buf.includes("\n")) {
        process.stdin.pause();
        const a = buf.trim().toLowerCase();
        res(a === "yes" || a === "y");
      }
    });
  });
}

// ── Knowledge Base ────────────────────────────────────────────────────────────
export class KnowledgeBase {
  private store = new Map<string, KnownSolution>();
  private readonly cry = getCrypto();
  private staticApps: StaticApp[] = [];

  constructor() { this.load(); }

  private load() {
    try {
      // 1. Initialise with static knowledge
      this.loadStatic();

      // 2. Load learned knowledge
      const raw = this.cry.readEncrypted<Record<string, KnownSolution>>(KNOWLEDGE_FILE);
      if (Object.keys(raw).length > 0) {
        for (const [k, v] of Object.entries(raw)) this.store.set(k, v);
      }
    } catch {}
  }

  private loadStatic() {
    try {
      const staticFile = path.join(path.dirname(KNOWLEDGE_FILE).replace(".ldp", "LDP/core-scripts"), "brain_knowledge.json");
      const fallbackFile = path.join(process.cwd(), "brain_knowledge.json");
      const target = fs.existsSync(staticFile) ? staticFile : fallbackFile;
      
      if (fs.existsSync(target)) {
        const raw = JSON.parse(fs.readFileSync(target, "utf-8"));
        if (raw.apps) {
          this.staticApps = raw.apps;
          for (const app of this.staticApps) {
            const appKey = `static_${app.name.toLowerCase()}`;
            this.store.set(appKey, {
              appKey,
              appName:      app.name,
              filePath:     app.pathPattern,
              method:       app.strategy,
              category:     app.category,
              params:       app.params,
              schema:       {},
              confidence:   1.0,
              solvedAt:     0,
              solvedOnOS:   "any",
              successCount: 0,
              failureCount: 0,
            });
          }
        }
      }
    } catch (e) {
      console.warn("[BRAIN] Failed to load static knowledge:", e);
    }
  }

  listStatic(): StaticApp[] { return this.staticApps; }

  public save() {
    const obj: Record<string, KnownSolution> = {};
    for (const [k, v] of this.store) obj[k] = v;
    this.cry.writeEncrypted(KNOWLEDGE_FILE, obj);
  }

  learn(sol: Omit<KnownSolution, "solvedAt" | "solvedOnOS" | "successCount" | "failureCount">, autoSave = true) {
    const ex = this.store.get(sol.appKey);
    this.store.set(sol.appKey, {
      ...sol,
      solvedAt:     Date.now() / 1000,
      solvedOnOS:   `${os.platform()} ${os.release()}`,
      successCount: (ex?.successCount ?? 0) + 1,
      failureCount: ex?.failureCount ?? 0,
    });
    if (autoSave) this.save();
    console.log(`[BRAIN] Learned: ${sol.appName} → ${sol.method}`);
  }

  recordFailure(appKey: string) {
    const ex = this.store.get(appKey);
    if (ex) { ex.failureCount++; this.save(); }
  }

  lookup(filePath: string): KnownSolution | null {
    for (const s of this.store.values()) if (s.filePath === filePath) return s;
    const needle = path.join(path.basename(path.dirname(filePath)), path.basename(filePath));
    for (const s of this.store.values()) {
      const c = path.join(path.basename(path.dirname(s.filePath)), path.basename(s.filePath));
      if (c === needle) return s;
    }
    return null;
  }

  lookupByApp(appName: string): KnownSolution | null {
    const n = appName.toLowerCase();
    for (const s of this.store.values()) if (s.appName.toLowerCase().includes(n)) return s;
    return null;
  }

  list(): KnownSolution[]  { return [...this.store.values()].sort((a,b) => b.solvedAt - a.solvedAt); }
  size(): number           { return this.store.size; }
  clear()                  { this.store.clear(); this.save(); }
}

// ── SQLite Schema Fingerprinting ────────────────────────────────────────────────
const SCHEMA_SIGS: Array<{ cols: string[]; app: string; cat: DataCategory; conf: number }> = [
  { cols:["url","visit_count","last_visit_time"],     app:"Browser History",  cat:"browser",   conf:0.85 },
  { cols:["body","sent_at","conversationId"],         app:"Messaging App",    cat:"messaging", conf:0.80 },
  { cols:["text","date","is_from_me","handle_id"],    app:"iMessage",         cat:"messaging", conf:0.90 },
  { cols:["title","content","created_at"],            app:"Notes App",        cat:"notes",     conf:0.75 },
  { cols:["amount","merchant","transaction_date"],    app:"Finance App",      cat:"finance",   conf:0.80 },
  { cols:["track_id","artist","play_count"],          app:"Music Player",     cat:"media",     conf:0.80 },
  { cols:["event_id","dtstart","summary"],            app:"Calendar App",     cat:"calendar",  conf:0.80 },
  { cols:["steps","heart_rate","start_date"],         app:"Health App",       cat:"health",    conf:0.82 },
  { cols:["name","email","phone"],                    app:"Contacts App",     cat:"contacts",  conf:0.75 },
  { cols:["channel","workspace","messages"],          app:"Slack",            cat:"messaging", conf:0.85 },
  { cols:["ZNOTE", "ZNOTEBODY", "ZACCOUNT"],          app:"Apple Notes",     cat:"notes",     conf:0.98 },
  { cols:["message", "handle", "chat"],               app:"iMessage",        cat:"messaging", conf:0.98 },
  { cols:["history_visits", "history_items"],         app:"Safari",          cat:"browser",   conf:0.98 },
  { cols:["ZCALENDARITEM", "ZCALENDAR", "ZATTACHMENT"], app:"Apple Calendar", cat:"calendar",  conf:0.98 },
  { cols:["ZABCDRECORD", "ZABCDEMAILADDRESS"],        app:"Apple Contacts", cat:"contacts",  conf:0.98 },
  { cols:["ZREMCDREMINDER", "ZREMCDLIST", "ZREMCDACCOUNT"], app:"Apple Reminders", cat:"calendar", conf:0.98 },
];

export function BrainFingerprint(tables: string[]): { appName: string; category: DataCategory; confidence: number } {
  if (!tables || tables.length === 0) return { appName: "unknown", category: "other", confidence: 0 };
  
  const all = [...tables].map(s => s.toLowerCase());
  
  let bestMatch = { app: "unknown", cat: "other" as DataCategory, conf: 0 };
  for (const s of SCHEMA_SIGS) {
    const hits = s.cols.filter(c => all.includes(c.toLowerCase())).length;
    if (hits > 0) {
      const matchConf = s.conf * (hits / s.cols.length);
      if (matchConf > bestMatch.conf) {
        bestMatch = { app: s.app, cat: s.cat, conf: matchConf };
      }
    }
  }
  
  // Rule 6: If we recognized it with >60% confidence, we ensure it's tracked in the static knowledge set 
  // (In a fuller AI system, we'd actually prompt an LLM for unseen tables here)
  return { appName: bestMatch.app, category: bestMatch.cat, confidence: bestMatch.conf };
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function getKeychainPw(service: string): string | null {
  try {
    return execSync(`security find-generic-password -s "${service}" -w`,
      { encoding: "utf-8", stdio: ["pipe","pipe","pipe"], timeout: 10000 }).trim();
  } catch { return null; }
}

function tryOpenSQLCipher(dbPath: string, pragmaKey: string, extra: string[] = []): DecryptResult {
  const tmp = path.join(os.tmpdir(), `ldp_brain_${crypto.randomBytes(6).toString("hex")}.db`);
  try {
    fs.copyFileSync(dbPath, tmp);
    for (const ext of ["-wal","-shm"]) {
      const src = dbPath + ext;
      if (fs.existsSync(src)) fs.copyFileSync(src, tmp + ext);
    }
    const DB = require("@signalapp/sqlcipher");
    const db = new DB(tmp, { cacheStatements: false });
    db.pragma(pragmaKey);
    for (const p of extra) db.pragma(p);
    const rows: any[] = db.prepare("SELECT name FROM sqlite_master WHERE type='table' LIMIT 5").all();
    db.close();
    return { success: rows.length > 0, rowCount: rows.length };
  } catch (e: any) {
    return { success: false, error: String(e?.message ?? e) };
  } finally {
    for (const ext of ["","-wal","-shm"]) { try { fs.unlinkSync(tmp + ext); } catch {} }
  }
}

function deriveChromiumKey(pw: string, iters = 1003): Buffer {
  return crypto.pbkdf2Sync(pw, "saltysalt", iters, 16, "sha1");
}

function decryptChromiumKey(hex: string, key: Buffer, ivFmt: "spaces"|"embedded"): string {
  const buf = Buffer.from(hex, "hex");
  if (buf.toString("utf8", 0, 3) !== "v10") throw new Error("Expected v10 prefix");
  const iv  = ivFmt === "spaces" ? Buffer.alloc(16, 0x20) : buf.subarray(3, 19);
  const ct  = ivFmt === "spaces" ? buf.subarray(3) : buf.subarray(19);
  const dec = crypto.createDecipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([dec.update(ct), dec.final()]).toString("utf8").trim();
}

function getEncryptedKey(appName: string, filePath: string): string | null {
  const candidates = [
    path.join(os.homedir(), `Library/Application Support/${appName}/config.json`),
    path.join(path.dirname(path.dirname(filePath)), "config.json"),
  ];
  for (const cp of candidates) {
    try { const cfg = JSON.parse(fs.readFileSync(cp, "utf-8")); if (cfg.encryptedKey) return cfg.encryptedKey; } catch {}
  }
  return null;
}

// ── Decryption Brain ──────────────────────────────────────────────────────────
export class DecryptionBrain {
  private readonly strategies: DecryptStrategy[];

  constructor(private readonly kb: KnowledgeBase, private readonly apiKey?: string) {
    this.strategies = this.buildStrategies();
  }

  async solve(filePath: string, appName: string, verbose = false): Promise<{ method: DecryptMethod; key?: string } | null> {
    // Check knowledge base first
    const known = this.kb.lookup(filePath) ?? this.kb.lookupByApp(appName);
    if (known && known.method !== "unknown") {
      if (verbose) console.log(`[BRAIN] Known: ${appName} → ${known.method}`);
      if (known.method === "plain_sqlite") return null;
      return { method: known.method, key: known.params.key as string | undefined };
    }

    // Run strategies ranked
    for (const s of [...this.strategies].sort((a,b) => a.rank - b.rank)) {
      if (verbose) console.log(`[BRAIN] Trying: ${s.description}`);
      let r: DecryptResult;
      try { r = await s.tryFn(filePath, appName); }
      catch (e: any) { r = { success: false, error: String(e?.message ?? e) }; }

      if (r.success) {
        if (verbose) console.log(`[BRAIN] ✓ Solved: ${appName} → ${s.method}`);
        const appKey = `${appName.toLowerCase().replace(/\s+/g,"_")}_${os.platform()}`;
        this.kb.learn({ 
          appKey, 
          appName, 
          filePath, 
          method: s.method, 
          category: guessCategory(appName),
          params: r.key ? { key: r.key } : {}, 
          schema: {},
          confidence: 1.0,
          totalRows: r.rowCount 
        });
        if (s.method === "plain_sqlite") return null;
        return { method: s.method, key: r.key };
      }
      if (verbose && r.error) console.log(`[BRAIN]   ✗ ${s.description}: ${r.error.slice(0, 80)}`);
    }

    // All local strategies failed — ask Claude (metadata only, no personal data)
    if (this.apiKey) await this.askClaude(filePath, appName, verbose);
    if (verbose) console.log(`[BRAIN] ✗ Could not decrypt: ${appName}`);
    return null;
  }

  private async askClaude(filePath: string, appName: string, verbose: boolean): Promise<void> {
    try {
      const fd = fs.openSync(filePath, "r");
      const buf = Buffer.alloc(32);
      fs.readSync(fd, buf, 0, 32, 0);
      fs.closeSync(fd);

      const prompt =
        `A local database could not be decrypted.\n` +
        `App name (guessed from path): "${appName}"\n` +
        `File header bytes (hex, first 32 — no personal data): ${buf.toString("hex")}\n` +
        `Platform: ${os.platform()} ${os.release()}\n\n` +
        `What SQLCipher decryption approach do you recommend? ` +
        `Reply in one sentence with the specific PRAGMA key format only.`;

      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": this.apiKey!, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-haiku-4-5-20251001", max_tokens: 150, messages: [{ role: "user", content: prompt }] }),
      });
      if (!resp.ok) return;
      const data = await resp.json() as any;
      const hint = data.content?.[0]?.text ?? "";
      if (verbose && hint) console.log(`[BRAIN] Claude suggests: ${hint}`);
    } catch {}
  }

  private buildStrategies(): DecryptStrategy[] {
    return [
      {
        method: "sqlcipher_chromium_safestore", description: "Chromium SafeStore (v10 format, spaces IV)", rank: 0.5,
        tryFn: async (fp, appName) => {
          // Check for static params first
          const known = this.kb.lookupByApp(appName);
          const service = (known?.params?.keychainService as string) ?? `${appName} Safe Storage`;
          const pw = getKeychainPw(service);
          if (!pw) return { success: false, error: `Keychain: "${service}" not found` };
          
          const encKey = getEncryptedKey(appName, fp);
          if (!encKey) return { success: false, error: "config.json / encryptedKey not found" };
          
          const iters = (known?.params?.iterations as number) ?? 1003;
          const ivFmt = (known?.params?.ivFormat as "spaces"|"embedded") ?? "spaces";

          try {
            const dbKey = decryptChromiumKey(encKey, deriveChromiumKey(pw, iters), ivFmt);
            const r = tryOpenSQLCipher(fp, `key = "x'${dbKey}'"`);
            return r.success ? { ...r, key: dbKey } : r;
          } catch (e: any) { return { success: false, error: String(e?.message ?? e) }; }
        },
      },
      {
        method: "plain_sqlite", description: "Plain unencrypted SQLite", rank: 0,
        tryFn: async (fp) => {
          try {
            const DB = require("better-sqlite3");
            const db = new DB(fp, { readonly: true, timeout: 2000 });
            const rows: any[] = db.prepare("SELECT name FROM sqlite_master WHERE type='table' LIMIT 5").all();
            db.close();
            return { success: rows.length > 0, rowCount: rows.length };
          } catch (e: any) { return { success: false, error: String(e?.message ?? e) }; }
        },
      },
      {
        method: "sqlcipher_pbkdf2_spaces_iv", description: "Chromium SafeStorage AES-128-CBC, IV = 16 spaces", rank: 1,
        tryFn: async (fp, appName) => {
          const pw = getKeychainPw(`${appName} Safe Storage`);
          if (!pw) return { success: false, error: `Keychain: "${appName} Safe Storage" not found` };
          const encKey = getEncryptedKey(appName, fp);
          if (!encKey) return { success: false, error: "config.json / encryptedKey not found" };
          try {
            const dbKey = decryptChromiumKey(encKey, deriveChromiumKey(pw), "spaces");
            const r = tryOpenSQLCipher(fp, `key = "x'${dbKey}'"`);
            return r.success ? { ...r, key: dbKey } : r;
          } catch (e: any) { return { success: false, error: String(e?.message ?? e) }; }
        },
      },
      {
        method: "sqlcipher_pbkdf2_embedded_iv", description: "Chromium SafeStorage AES-128-CBC, IV = bytes 3-19", rank: 2,
        tryFn: async (fp, appName) => {
          const pw = getKeychainPw(`${appName} Safe Storage`);
          if (!pw) return { success: false, error: `Keychain: "${appName} Safe Storage" not found` };
          const encKey = getEncryptedKey(appName, fp);
          if (!encKey) return { success: false, error: "config.json / encryptedKey not found" };
          try {
            const dbKey = decryptChromiumKey(encKey, deriveChromiumKey(pw), "embedded");
            const r = tryOpenSQLCipher(fp, `key = "x'${dbKey}'"`);
            return r.success ? { ...r, key: dbKey } : r;
          } catch (e: any) { return { success: false, error: String(e?.message ?? e) }; }
        },
      },
      {
        method: "sqlcipher_v3_compat", description: "SQLCipher v3 compat with Chromium key", rank: 3,
        tryFn: async (fp, appName) => {
          const pw = getKeychainPw(`${appName} Safe Storage`);
          if (!pw) return { success: false, error: "Keychain not found" };
          const encKey = getEncryptedKey(appName, fp);
          if (!encKey) return { success: false, error: "No encryptedKey" };
          try {
            const dbKey = decryptChromiumKey(encKey, deriveChromiumKey(pw), "spaces");
            const r = tryOpenSQLCipher(fp, `key = "x'${dbKey}'"`, ["cipher_compatibility = 3"]);
            return r.success ? { ...r, key: dbKey } : r;
          } catch (e: any) { return { success: false, error: String(e?.message ?? e) }; }
        },
      },
      {
        method: "sqlcipher_direct_hex", description: "Keychain value used directly as 64-char hex key", rank: 4,
        tryFn: async (fp, appName) => {
          const pw = getKeychainPw(`${appName} Safe Storage`);
          if (!pw) return { success: false, error: "Keychain not found" };
          if (!/^[0-9a-f]{64}$/i.test(pw)) return { success: false, error: "Not a 64-char hex key" };
          const r = tryOpenSQLCipher(fp, `key = "x'${pw}'"`);
          return r.success ? { ...r, key: pw } : r;
        },
      },
    ];
  }
}

// ── Error Brain ───────────────────────────────────────────────────────────────
export class ErrorBrain {
  diagnose(error: unknown, appName: string, filePath: string): BrainDiagnosis {
    const msg = String((error as any)?.message ?? error).toLowerCase();
    if (msg.includes("file is not a database") || msg.includes("sqlite_notadb"))
      return { errorType: "decrypt_failed", appName, filePath, suggestion: "Database is encrypted — running experiment engine", recoverable: true, retryWith: "sqlcipher_pbkdf2_spaces_iv" };
    if (msg.includes("enoent") || msg.includes("no such file"))
      return { errorType: "file_not_found", appName, filePath, suggestion: `${appName} not installed or moved`, recoverable: false };
    if (msg.includes("eacces") || msg.includes("permission denied"))
      return { errorType: "permission_denied", appName, filePath, suggestion: "Full Disk Access required — System Settings → Privacy", recoverable: false };
    if (msg.includes("busy") || msg.includes("locked"))
      return { errorType: "file_locked", appName, filePath, suggestion: "App has DB locked — will copy to /tmp and retry", recoverable: true };
    if (msg.includes("no such table") || msg.includes("no such column"))
      return { errorType: "schema_changed", appName, filePath, suggestion: `${appName} updated its schema — re-running discovery`, recoverable: true };
    return { errorType: "unknown", appName, filePath, suggestion: `Unknown error — logged: ${msg.slice(0, 100)}`, recoverable: false };
  }
}

// ── Main LDPBrain ─────────────────────────────────────────────────────────────
export class LDPBrain {
  readonly approvals: ApprovalManager;
  readonly knowledge: KnowledgeBase;
  readonly decrypt:   DecryptionBrain;
  readonly errors:    ErrorBrain;
  private  v: boolean;

  constructor(opts: BrainOptions = {}) {
    this.v         = opts.verbose ?? false;
    this.approvals = new ApprovalManager();
    this.knowledge = new KnowledgeBase();
    this.decrypt   = new DecryptionBrain(this.knowledge, opts.apiKey);
    this.errors    = new ErrorBrain();
  }

  async start(): Promise<this> {
    fs.mkdirSync(LDP_DIR, { recursive: true, mode: 0o700 });
    if (this.v) {
      console.log(`[BRAIN] Started — ${this.knowledge.size()} known solutions`);
      console.log(`[BRAIN] Approved: ${this.approvals.listApproved().join(", ") || "none"}`);
    }
    return this;
  }

  async connectApp(
    filePath:  string,
    appName:   string,
    category:  DataCategory,
    promptFn?: (msg: string) => Promise<boolean>,
  ): Promise<{ method: DecryptMethod; key?: string } | "denied" | "unsolvable"> {
    const ok = await this.approvals.request(category, appName, promptFn);
    if (!ok) return "denied";
    const sol = await this.decrypt.solve(filePath, appName, this.v);
    if (sol === null) return { method: "plain_sqlite" };
    return sol ?? "unsolvable";
  }

  report() {
    return {
      approvedCategories: this.approvals.listApproved(),
      knownSolutions:     this.knowledge.size(),
      solutions:          this.knowledge.list(),
    };
  }
}

// ── Utility: guess category from app name ─────────────────────────────────────
export function guessCategory(appName: string): DataCategory {
  const n = appName.toLowerCase();
  if (/signal|imessage|whatsapp|telegram|slack|discord/.test(n)) return "messaging";
  if (/chrome|firefox|safari|brave|chromium/.test(n))            return "browser";
  if (/vscode|code|cursor|git|terminal|shell/.test(n))           return "developer";
  if (/health|fitness|workout|steps|heart/.test(n))              return "health";
  if (/bank|finance|money|transaction|budget/.test(n))           return "finance";
  if (/notes|obsidian|notion|bear|memo/.test(n))                 return "notes";
  if (/spotify|music|podcast|plex/.test(n))                      return "media";
  if (/contact|address.*book/.test(n))                           return "contacts";
  if (/calendar|reminder|event|schedule/.test(n))                return "calendar";
  return "other";
}
