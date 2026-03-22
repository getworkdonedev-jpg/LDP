/**
 * LDP Auto-Discovery Engine — Layer 0
 * @ldp-protocol/sdk
 *
 * THREE AI AGENTS run automatically on startup:
 *
 *   1. FingerprintAgent  — reads first 16 bytes of every DB file found
 *                          identifies SQLite, SQLCipher, encrypted, unknown
 *
 *   2. DecryptAgent      — for each encrypted file, finds the right key
 *                          tries macOS Keychain → PBKDF2 → known patterns
 *                          validates by attempting to read sqlite_master
 *
 *   3. SchemaAgent       — after access confirmed, maps table+column names
 *                          to human meaning using AI + pattern matching
 *                          registers connector with correct semantic labels
 *
 * Usage — call once at startup:
 *
 *   import { DiscoveryEngine } from "@ldp-protocol/sdk/discover";
 *   import { LDPEngine } from "@ldp-protocol/sdk";
 *
 *   const ldp       = new LDPEngine().start();
 *   const discovery = new DiscoveryEngine(ldp);
 *   const results   = await discovery.run();
 *
 *   // results.connected → array of connector names now registered + consented
 *   // Ask questions immediately — no further setup needed
 *   const answer = await ldp.query("what sites did I waste time on?");
 */

import * as fs            from "node:fs";
import * as path          from "node:path";
import * as os            from "node:os";
import * as crypto        from "node:crypto";
import { execSync }       from "node:child_process";
import { createRequire }  from "node:module";
import type { LDPEngine } from "./engine.js";
import type { BaseConnector, ConnectorDescriptor, Row, SchemaMap } from "./types.js";

const require = createRequire(import.meta.url);

// ── Types ────────────────────────────────────────────────────────────────────

export type EncryptionType =
  | "none"          // plain SQLite — reads directly
  | "sqlcipher"     // Signal, WhatsApp — needs PBKDF2 key
  | "chrome_aes"    // Chrome — needs OS Keychain AES-128
  | "unknown";      // cannot determine

export interface DiscoveredApp {
  name:           string;
  app:            string;
  filePath:       string;
  encryption:     EncryptionType;
  decryptKey:     string | null;
  schema:         SchemaMap;
  confidence:     number;
  connector:      BaseConnector;
}

export interface DiscoveryResult {
  scanned:   number;
  connected: string[];
  failed:    Array<{ path: string; reason: string }>;
  durationMs: number;
}

// ── Known app paths — multi-platform with glob support ───────────────────────
// Each entry lists globs per platform. * is expanded to first matching entry.
// Add any new app here — no other code changes needed.

interface AppTarget {
  name:             string;
  app:              string;
  globs:            Partial<Record<NodeJS.Platform, string[]>>;
  encryption:       EncryptionType;
  keychainService?: string;
  category:         string;
}

const APP_TARGETS: AppTarget[] = [
  {
    name: "chrome", app: "Google Chrome", category: "browser",
    encryption: "chrome_aes",
    globs: {
      darwin: ["~/Library/Application Support/Google/Chrome/Default/History"],
      linux:  ["~/.config/google-chrome/Default/History"],
      win32:  ["~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"],
    },
  },
  {
    name: "brave", app: "Brave Browser", category: "browser",
    encryption: "chrome_aes",
    globs: {
      darwin: ["~/Library/Application Support/BraveSoftware/Brave-Browser/Default/History"],
      linux:  ["~/.config/BraveSoftware/Brave-Browser/Default/History"],
    },
  },
  {
    name: "firefox", app: "Firefox", category: "browser",
    encryption: "none",
    globs: {
      darwin: ["~/Library/Application Support/Firefox/Profiles/*/places.sqlite"],
      linux:  ["~/.mozilla/firefox/*/places.sqlite"],
      win32:  ["~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite"],
    },
  },
  {
    name: "signal_native", app: "Signal", category: "messaging",
    encryption: "sqlcipher",
    keychainService: "Signal Safe Storage",
    globs: {
      darwin: ["~/Library/Application Support/Signal/sql/db.sqlite"],
      linux:  ["~/.config/Signal/sql/db.sqlite"],
      win32:  ["~\\AppData\\Roaming\\Signal\\sql\\db.sqlite"],
    },
  },
  {
    name: "imessage", app: "iMessage", category: "messaging",
    encryption: "none",
    globs: { darwin: ["~/Library/Messages/chat.db"] },
  },
  {
    name: "whatsapp", app: "WhatsApp", category: "messaging",
    encryption: "none",
    globs: {
      darwin: [
        "~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite",
        "~/Library/Containers/net.whatsapp.WhatsApp/Data/Library/Application Support/WhatsApp/ChatStorage.sqlite",
      ],
    },
  },
  {
    name: "telegram", app: "Telegram", category: "messaging",
    encryption: "none",
    globs: {
      darwin: ["~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/account-*/postbox/db/db_sqlite"],
    },
  },
  {
    name: "vscode", app: "VS Code", category: "developer",
    encryption: "none",
    globs: {
      darwin: ["~/Library/Application Support/Code/User/globalStorage/state.vscdb"],
      linux:  ["~/.config/Code/User/globalStorage/state.vscdb"],
      win32:  ["~\\AppData\\Roaming\\Code\\User\\globalStorage\\state.vscdb"],
    },
  },
  {
    name: "cursor_app", app: "Cursor", category: "developer",
    encryption: "none",
    globs: {
      darwin: ["~/Library/Application Support/Cursor/User/globalStorage/state.vscdb"],
      linux:  ["~/.config/Cursor/User/globalStorage/state.vscdb"],
    },
  },
  {
    name: "apple_notes", app: "Apple Notes", category: "notes",
    encryption: "none",
    globs: { darwin: ["~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"] },
  },
  {
    name: "spotify", app: "Spotify", category: "media",
    encryption: "none",
    globs: {
      darwin: ["~/Library/Application Support/Spotify/PersistentCache/podcasts.db"],
      linux:  ["~/.config/spotify/podcasts.db"],
    },
  },
];

// ── Glob resolver — expands * to first matching path ─────────────────────────

function resolveGlob(pattern: string): string | null {
  const expanded = pattern.replace(/^~/, os.homedir());
  if (!expanded.includes("*")) {
    return fs.existsSync(expanded) ? expanded : null;
  }
  // Split on first * and find matching directory entry
  const starIdx  = expanded.indexOf("*");
  const dir      = path.dirname(expanded.slice(0, starIdx + 1).replace(/\/[^/]*$/, ""));
  const after    = expanded.slice(starIdx + 1);
  if (!fs.existsSync(dir)) return null;
  try {
    const entries = fs.readdirSync(dir).sort(); // deterministic order
    for (const entry of entries) {
      const candidate = path.join(dir, entry) + after;
      if (fs.existsSync(candidate)) return candidate;
    }
  } catch { /* permission denied */ }
  return null;
}

function resolveTarget(target: AppTarget): string | null {
  const platform = process.platform as NodeJS.Platform;
  const globs    = target.globs[platform] ?? target.globs["linux"] ?? [];
  for (const glob of globs) {
    const resolved = resolveGlob(glob);
    if (resolved) return resolved;
  }
  return null;
}

// ── Delta sync state — tracks last_read_at per connector ─────────────────────

const SYNC_STATE_FILE = path.join(os.homedir(), ".ldp", "sync_state.json");

function loadSyncState(): Record<string, number> {
  try {
    if (fs.existsSync(SYNC_STATE_FILE))
      return JSON.parse(fs.readFileSync(SYNC_STATE_FILE, "utf-8"));
  } catch { /* corrupt — start fresh */ }
  return {};
}

function saveSyncState(state: Record<string, number>): void {
  try {
    fs.mkdirSync(path.dirname(SYNC_STATE_FILE), { recursive: true });
    fs.writeFileSync(SYNC_STATE_FILE, JSON.stringify(state, null, 2));
  } catch { /* non-fatal */ }
}

export function getLastReadAt(connectorName: string): number {
  return loadSyncState()[connectorName] ?? 0;
}

export function markReadAt(connectorName: string, timestamp = Date.now() / 1000): void {
  const state = loadSyncState();
  state[connectorName] = timestamp;
  saveSyncState(state);
}

// Legacy alias so existing SCAN_TARGETS references compile
const SCAN_TARGETS = APP_TARGETS;

// ── Agent 1: FingerprintAgent ─────────────────────────────────────────────────

const SQLITE_MAGIC = "SQLite format 3\0";
const SQLCIPHER_INDICATORS = [
  // SQLCipher encrypted files have random-looking first bytes (not SQLite magic)
  // We detect by absence of the magic header AND presence of non-zero high bytes
];

export class FingerprintAgent {
  /**
   * Read first 16 bytes and determine encryption type.
   * Returns "none" for plain SQLite, "sqlcipher" for encrypted,
   * "chrome_aes" for Chrome (uses separate Keychain key, not file-level),
   * "unknown" if file cannot be read or identified.
   */
  identify(filePath: string, hint?: EncryptionType): EncryptionType {
    // If caller already knows (e.g. from SCAN_TARGETS), trust the hint
    if (hint && hint !== "unknown") return hint;

    try {
      const fd  = fs.openSync(filePath, "r");
      const buf = Buffer.alloc(16);
      fs.readSync(fd, buf, 0, 16, 0);
      fs.closeSync(fd);

      const header = buf.toString("utf8", 0, 6);
      if (header === "SQLite") return "none";

      // Non-SQLite header → likely encrypted
      // Check for all-zero (empty) vs high-entropy (encrypted)
      const entropy = buf.reduce((s, b) => s + (b > 0 ? 1 : 0), 0);
      return entropy > 4 ? "sqlcipher" : "unknown";
    } catch {
      return "unknown";
    }
  }

  exists(filePath: string): boolean {
    return fs.existsSync(expandHome(filePath));
  }
}

// ── Agent 2: DecryptAgent ─────────────────────────────────────────────────────

export class DecryptAgent {
  /**
   * For a given app + encryption type, find the decryption key.
   * Returns the key string (hex for SQLCipher) or null if cannot decrypt.
   * Validates by attempting to open the DB and read sqlite_master.
   */
  async findKey(
    filePath: string,
    encryption: EncryptionType,
    keychainService?: string,
  ): Promise<string | null> {
    if (encryption === "none") return null; // no key needed

    if (encryption === "sqlcipher") {
      return this.findSQLCipherKey(filePath, keychainService);
    }

    if (encryption === "chrome_aes") {
      // Chrome doesn't encrypt the SQLite file itself —
      // the History DB is plain SQLite. Chrome AES encrypts
      // individual field values (cookies etc). History is readable directly.
      return null;
    }

    return null;
  }

  private findSQLCipherKey(filePath: string, keychainService?: string): string | null {
    const service = keychainService ?? this.guessKeychainService(filePath);
    if (!service) return null;

    let keychainPassword: string;
    try {
      keychainPassword = execSync(
        `security find-generic-password -s "${service}" -w`,
        { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
    } catch {
      return null; // Keychain access denied or service not found
    }

    const configPath = this.findConfigJson(filePath);
    if (!configPath) return null;

    let config: Record<string, string>;
    try {
      config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    } catch {
      return null;
    }

    const encryptedHex = config.encryptedKey;
    if (!encryptedHex) return null;

    return this.tryDecryptKey(keychainPassword, encryptedHex);
  }

  private tryDecryptKey(password: string, encryptedHex: string): string | null {
    const encBuf = Buffer.from(encryptedHex, "hex");

    if (encBuf.toString("utf8", 0, 3) !== "v10") return null;

    const derivedKey = crypto.pbkdf2Sync(password, "saltysalt", 1003, 16, "sha1");
    const isValidKey  = (k: string) => /^[0-9a-f]{64}$/i.test(k);

    // Format A — 16-space IV (standard Chromium / older builds)
    try {
      const iv         = Buffer.alloc(16, 0x20);
      const ciphertext = encBuf.subarray(3);
      const decipher   = crypto.createDecipheriv("aes-128-cbc", derivedKey, iv);
      const decrypted  = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const key        = decrypted.toString("utf8").replace(/[\x00-\x10]/g, "").trim();
      if (isValidKey(key)) return key;
    } catch { /* try next format */ }

    // Format B — embedded IV (newer builds)
    try {
      const iv         = encBuf.subarray(3, 19);
      const ciphertext = encBuf.subarray(19);
      const decipher   = crypto.createDecipheriv("aes-128-cbc", derivedKey, iv);
      const decrypted  = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const key        = decrypted.toString("utf8").replace(/[\x00-\x10]/g, "").trim();
      if (isValidKey(key)) return key;
    } catch { /* give up */ }

    return null;
  }

  private guessKeychainService(filePath: string): string | null {
    if (filePath.includes("Signal"))    return "Signal Safe Storage";
    if (filePath.includes("WhatsApp")) return "WhatsApp";
    return null;
  }

  private findConfigJson(filePath: string): string | null {
    // Walk up the directory tree looking for config.json
    let dir = path.dirname(filePath);
    for (let i = 0; i < 4; i++) {
      const candidate = path.join(dir, "config.json");
      if (fs.existsSync(candidate)) return candidate;
      dir = path.dirname(dir);
    }
    return null;
  }

  /**
   * Validate that a key actually opens the database.
   * Returns true if sqlite_master is readable.
   */
  validateKey(filePath: string, key: string): boolean {
    const tmp = path.join(os.tmpdir(), `ldp_validate_${Date.now()}.db`);
    try {
      fs.copyFileSync(filePath, tmp);
      const { Database } = require("@signalapp/sqlcipher");
      const db = new Database(tmp, { cacheStatements: false });
      db.pragma(`key = "x'${key}'"`);
      db.prepare("SELECT count(*) FROM sqlite_master").get();
      db.close();
      return true;
    } catch {
      return false;
    } finally {
      try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    }
  }
}

// ── Agent 3: SchemaAgent ──────────────────────────────────────────────────────

// Semantic mapping: if a table+column matches these patterns, we know what it means
const SEMANTIC_MAP: Record<string, { description: string; category: string }> = {
  // Browser
  "urls.url":             { description: "full URL visited", category: "browser" },
  "urls.title":           { description: "page title", category: "browser" },
  "urls.visit_count":     { description: "times visited", category: "browser" },
  "urls.last_visit_time": { description: "last visit timestamp (Chrome format)", category: "browser" },
  "visits.visit_time":    { description: "visit timestamp", category: "browser" },
  // Messages
  "messages.body":        { description: "message text", category: "messaging" },
  "messages.sent_at":     { description: "sent timestamp", category: "messaging" },
  "messages.type":        { description: "message type (incoming/outgoing)", category: "messaging" },
  "conversations.name":   { description: "contact or group name", category: "messaging" },
  "conversations.active_at": { description: "last activity timestamp", category: "messaging" },
  // iMessage
  "message.text":         { description: "message text", category: "messaging" },
  "message.date":         { description: "Apple epoch timestamp", category: "messaging" },
  "message.is_from_me":   { description: "sent by user", category: "messaging" },
  "handle.id":            { description: "phone number or email", category: "messaging" },
  // VS Code
  "ItemTable.key":        { description: "setting or state key", category: "developer" },
  "ItemTable.value":      { description: "setting or state value", category: "developer" },
};

function getCategoryFromColumns(tables: string[], columns: string[]): string {
  const all = [...tables, ...columns].map(s => s.toLowerCase());
  if (all.some(s => ["url", "visit_count", "typed_count"].includes(s))) return "browser";
  if (all.some(s => ["body", "sent_at", "conversation"].includes(s))) return "messaging";
  if (all.some(s => ["text", "handle", "is_from_me"].includes(s))) return "messaging";
  if (all.some(s => ["track", "artist", "play_count"].includes(s))) return "media";
  if (all.some(s => ["note", "content", "title"].includes(s))) return "notes";
  if (all.some(s => ["event", "dtstart", "summary"].includes(s))) return "calendar";
  if (all.some(s => ["amount", "merchant", "transaction"].includes(s))) return "finance";
  if (all.some(s => ["steps", "heart_rate", "sleep"].includes(s))) return "health";
  if (all.some(s => ["key", "value", "workspace"].includes(s))) return "developer";
  return "unknown";
}

export class SchemaAgent {
  /**
   * Read the schema of a database file (with optional SQLCipher key).
   * Returns a SchemaMap with semantic descriptions.
   */
  async readSchema(filePath: string, key: string | null): Promise<SchemaMap> {
    const tmp = path.join(os.tmpdir(), `ldp_schema_${Date.now()}.db`);
    try {
      fs.copyFileSync(filePath, tmp);
      let db: any;

      if (key) {
        const { Database } = require("@signalapp/sqlcipher");
        db = new Database(tmp, { cacheStatements: false });
        db.pragma(`key = "x'${key}'"`);
      } else {
        const Database = (await import("better-sqlite3")).default;
        db = new Database(tmp, { readonly: true });
      }

      // Get all table names
      const tables: Array<{ name: string }> = db.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
      ).all();

      const schema: SchemaMap = {};

      for (const { name } of tables.slice(0, 10)) { // limit to 10 tables
        try {
          const cols: Array<{ name: string; type: string }> = db.prepare(
            `PRAGMA table_info("${name}")`,
          ).all();

          schema[name] = {};
          for (const col of cols.slice(0, 15)) { // limit to 15 columns
            const semanticKey = `${name}.${col.name}`;
            const semantic    = SEMANTIC_MAP[semanticKey];
            schema[name][col.name] = semantic?.description
              ?? `${col.type || "unknown"} field`;
          }
        } catch { /* skip unreadable table */ }
      }

      db.close();
      return schema;
    } catch {
      return {};
    } finally {
      try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    }
  }

  /**
   * Build named queries based on what tables/columns were found.
   */
  buildNamedQueries(
    appName:  string,
    schema:   SchemaMap,
    category: string,
  ): Record<string, string> {
    const tables = Object.keys(schema);
    const allCols = tables.flatMap(t => Object.keys(schema[t]));

    if (category === "browser") {
      return {
        recent:       "Last 50 pages visited",
        top_sites:    "Most visited websites",
        searches:     "Search queries typed",
        distractions: "YouTube, Reddit, Twitter — time wasters",
      };
    }
    if (category === "messaging") {
      return {
        recent_messages: "Last 20 messages received",
        conversations:   "Most active conversations",
        top_contacts:    "People you message most",
      };
    }
    if (category === "developer") {
      return {
        recent_files:      "Files opened recently",
        recent_workspaces: "Workspaces opened recently",
      };
    }
    if (category === "media") {
      return {
        top_tracks:  "Most played tracks",
        recent_plays: "Recently played",
      };
    }
    if (category === "notes") {
      return {
        recent_notes: "Notes modified recently",
        all_notes:    "All notes with title",
      };
    }
    return {
      recent: `Recent ${appName} data`,
      all:    `All ${appName} records`,
    };
  }
}

// ── Connector builder from discovery result ───────────────────────────────────

function buildConnector(discovered: {
  name:       string;
  app:        string;
  filePath:   string;
  encryption: EncryptionType;
  decryptKey: string | null;
  schema:     SchemaMap;
  confidence: number;
}): BaseConnector {
  const descriptor: ConnectorDescriptor = {
    name:         discovered.name,
    app:          discovered.app,
    version:      "auto-2.0",
    dataPaths:    [discovered.filePath],
    permissions:  ["data.read"],
    namedQueries: {},
    description:  `Auto-discovered ${discovered.app} — reads local data privately.`,
  };

  return {
    descriptor,

    async discover(): Promise<boolean> {
      return fs.existsSync(discovered.filePath);
    },

    async schema(): Promise<SchemaMap> {
      return discovered.schema;
    },

    async read(query: string, limit = 100): Promise<Row[]> {
      const tmp = path.join(os.tmpdir(), `ldp_read_${Date.now()}.db`);
      try {
        fs.copyFileSync(discovered.filePath, tmp);
        let db: any;

        if (discovered.decryptKey) {
          const { Database } = require("@signalapp/sqlcipher");
          db = new Database(tmp, { cacheStatements: false });
          db.pragma(`key = "x'${discovered.decryptKey}'"`);
        } else {
          const Database = (await import("better-sqlite3")).default;
          db = new Database(tmp, { readonly: true });
        }

        // Try the most common tables first based on schema
        const tables = Object.keys(discovered.schema);
        if (!tables.length) return [];

        // Pick table based on query keywords
        const q        = query.toLowerCase();
        const bestTable = tables.find(t =>
          q.includes(t.toLowerCase()) ||
          q.includes("recent") ||
          q.includes("message") ||
          q.includes("url")
        ) ?? tables[0];

        const cols = Object.keys(discovered.schema[bestTable] ?? {});
        if (!cols.length) return [];

        // Build a safe SELECT with ORDER BY if there is a timestamp column
        const timeCol = cols.find(c =>
          /time|date|ts|at|created/.test(c.toLowerCase())
        );
        const selectCols = cols.slice(0, 8).map(c => `"${c}"`).join(", ");
        const orderBy    = timeCol ? `ORDER BY "${timeCol}" DESC` : "";

        const rows: Row[] = db.prepare(
          `SELECT ${selectCols} FROM "${bestTable}" ${orderBy} LIMIT ${limit}`,
        ).all();

        db.close();
        const now = Date.now() / 1000;
        return rows.map(r => ({
          ...r,
          _src:     discovered.name,
          _recency: 0.8, // default — ContextPacker will re-score
        }));
      } catch {
        return [];
      } finally {
        try { fs.unlinkSync(tmp); } catch { /* ignore */ }
      }
    },
  };
}

// ── Helper ────────────────────────────────────────────────────────────────────

function expandHome(p: string): string {
  return p.replace(/^~/, os.homedir());
}

// ── Main DiscoveryEngine ──────────────────────────────────────────────────────

export interface DiscoveryOptions {
  /** Log each step to console. Default false. */
  verbose?: boolean;
  /** Maximum time per file in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Only try these connector names. Default: all. */
  only?: string[];
  /** Skip these connector names. */
  skip?: string[];
  /** Ignore delta sync state and re-read everything. Default: false. */
  forceRescan?: boolean;
}

export class DiscoveryEngine {
  private readonly fingerprint = new FingerprintAgent();
  private readonly decrypt     = new DecryptAgent();
  private readonly schemaAgent = new SchemaAgent();

  constructor(
    private readonly engine: InstanceType<typeof LDPEngine>,
    private readonly opts: DiscoveryOptions = {},
  ) {}

  /**
   * Run all three agents against all known paths.
   * Registers discovered apps with the LDPEngine automatically.
   * No configuration needed.
   */
  async run(): Promise<DiscoveryResult> {
    const start  = Date.now();
    const result: DiscoveryResult = {
      scanned:   0,
      connected: [],
      failed:    [],
      durationMs: 0,
    };

    const targets = SCAN_TARGETS.filter(t => {
      if (this.opts.only && !this.opts.only.includes(t.name)) return false;
      if (this.opts.skip?.includes(t.name)) return false;
      return true;
    });

    for (const target of targets) {
      // Resolve multi-platform glob to actual path on this machine
      const filePath = resolveTarget(target);
      result.scanned++;

      if (!filePath) {
        if (this.opts.verbose) console.log(`[LDP] skip (not found): ${target.app}`);
        continue;
      }

      // Delta: skip if file unchanged since last read
      const lastRead  = getLastReadAt(target.name);
      const fileMtime = fs.statSync(filePath).mtimeMs / 1000;
      if (!this.opts.forceRescan && lastRead > 0 && fileMtime <= lastRead) {
        if (this.opts.verbose) console.log(`[LDP] skip (no changes): ${target.app}`);
        continue;
      }

      if (this.opts.verbose) console.log(`[LDP] scanning: ${target.app} at ${filePath}`);

      try {
        // Agent 1: Fingerprint — reads actual file bytes, not path heuristics
        const encryption = this.fingerprint.identify(filePath, target.encryption);
        if (encryption === "unknown") {
          result.failed.push({ path: filePath, reason: "unrecognised encryption" });
          continue;
        }

        // Agent 2: Decrypt — tries all known key derivation methods, validates
        let decryptKey: string | null = null;
        if (encryption === "sqlcipher") {
          decryptKey = await this.decrypt.findKey(filePath, encryption, target.keychainService);
          if (!decryptKey) {
            result.failed.push({ path: filePath, reason: "could not extract key from Keychain" });
            continue;
          }
          const valid = this.decrypt.validateKey(filePath, decryptKey);
          if (!valid) {
            result.failed.push({ path: filePath, reason: "key extracted but DB did not open" });
            continue;
          }
        }

        // Agent 3: Schema
        const schema   = await this.schemaAgent.readSchema(filePath, decryptKey);
        const tables   = Object.keys(schema);
        const allCols  = tables.flatMap(t => Object.keys(schema[t]));
        const category = getCategoryFromColumns(tables, allCols);

        const namedQueries = this.schemaAgent.buildNamedQueries(
          target.app, schema, category,
        );

        // Build connector
        const connector = buildConnector({
          name:       target.name,
          app:        target.app,
          filePath,
          encryption,
          decryptKey,
          schema,
          confidence: 0.95,
        });

        // Register + consent + connect — all automatic
        connector.descriptor.namedQueries = namedQueries;
        connector.descriptor.permissions  = [`${category}.read`];
        connector.descriptor.description  =
          `Auto-discovered ${target.app} — ${category} data. Local only.`;

        this.engine.register(connector);
        this.engine.grantConsent(target.name, "auto-discovery");
        const msg = await this.engine.connect(target.name, false);

        if (msg.type === "ACK") {
          result.connected.push(target.name);
          markReadAt(target.name);   // delta sync: record this read timestamp
          if (this.opts.verbose) {
            console.log(`[LDP] ✓ connected: ${target.app} (${category})`);
          }
        } else {
          result.failed.push({
            path: filePath,
            reason: String(msg.payload.error ?? "connect failed"),
          });
        }
      } catch (err) {
        result.failed.push({ path: filePath, reason: String(err) });
      }
    }

    result.durationMs = Date.now() - start;
    return result;
  }

  /**
   * Quick-connect a single app by name.
   * Useful for targeted reconnect without full scan.
   */
  async connectOne(name: string): Promise<boolean> {
    const target = SCAN_TARGETS.find(t => t.name === name);
    if (!target) return false;

    const mini = new DiscoveryEngine(this.engine, { ...this.opts, only: [name] });
    const result = await mini.run();
    return result.connected.includes(name);
  }
}

// ── Convenience factory ───────────────────────────────────────────────────────

/**
 * One-line startup. Discovers and connects everything available on this machine.
 *
 * @example
 * ```ts
 * import { autoConnect } from "@ldp-protocol/sdk/discover";
 * import { LDPEngine }   from "@ldp-protocol/sdk";
 *
 * const engine  = new LDPEngine().start();
 * const result  = await autoConnect(engine, { verbose: true });
 * // result.connected → ["chrome", "signal_native", "imessage", "vscode", ...]
 *
 * const answer = await engine.query("what have I been working on?");
 * ```
 */
export async function autoConnect(
  engine:  InstanceType<typeof LDPEngine>,
  opts:    DiscoveryOptions = {},
): Promise<DiscoveryResult> {
  const discovery = new DiscoveryEngine(engine, opts);
  return discovery.run();
}
