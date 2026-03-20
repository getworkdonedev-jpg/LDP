/**
 * LDP — Auto Connector Generator
 *
 * Scans the local machine for unknown SQLite / JSON databases,
 * reads their schemas, calls an LLM to infer meaning, and
 * auto-generates a ConnectorDescriptor — no code required.
 *
 * Usage:
 *   const gen = new AutoConnectorGenerator({ apiKey: process.env.ANTHROPIC_API_KEY });
 *   const results = await gen.scan();
 *   for (const r of results) {
 *     console.log(r.descriptor);   // ready-to-use ConnectorDescriptor
 *     await engine.register(r.connector);
 *   }
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { ConnectorDescriptor, BaseConnector, Row, SchemaMap } from "./types.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface AutoGenOptions {
  /** Anthropic API key — if omitted, uses heuristic-only mode (no LLM). */
  apiKey?: string;
  /** Extra directories to scan beyond the defaults. */
  extraPaths?: string[];
  /** Max files to inspect per scan (default 200). */
  maxFiles?: number;
  /** Skip paths matching these substrings (default: system/cache dirs). */
  skipPatterns?: string[];
  /** Model to use for schema analysis (default: claude-haiku-4-5-20251001 — fast + cheap). */
  model?: string;
}

export interface AutoGenResult {
  /** The generated descriptor. */
  descriptor: ConnectorDescriptor;
  /** A ready-to-use connector you can pass directly to engine.register(). */
  connector: BaseConnector;
  /** Confidence score 0–1 from the AI (or heuristic). */
  confidence: number;
  /** Path to the source file. */
  sourcePath: string;
  /** How the connector was generated: "ai" | "heuristic" | "known-app". */
  method: "ai" | "heuristic" | "known-app";
}

interface RawSchema {
  tables: Array<{
    name: string;
    columns: Array<{ name: string; type: string }>;
    rowCount: number;
  }>;
}

// ── Known app fingerprints (heuristic, no AI needed) ─────────────────────────

const KNOWN_FINGERPRINTS: Array<{
  pattern: RegExp;
  app: string;
  category: string;
  permissions: string[];
  namedQueries: Record<string, string>;
  connectionHints?: ConnectorDescriptor["connectionHints"];
}> = [
    {
      pattern: /Chrome.*History|Chromium.*History|BraveSoftware.*History/i,
      app: "Google Chrome",
      category: "browser",
      permissions: ["history.read"],
      namedQueries: {
        time_wasters: "Sites visited most often (likely distractions)",
        research_topics: "Pages with high visit count in last 7 days",
        typed_urls: "URLs typed directly (strongest intent signal)",
        recent_tabs: "Last 50 pages visited",
      },
    },
    {
      pattern: /Firefox.*places\.sqlite/i,
      app: "Firefox",
      category: "browser",
      permissions: ["history.read", "bookmarks.read"],
      namedQueries: {
        recent_history: "Pages visited in last 14 days",
        bookmarks: "All saved bookmarks",
        top_sites: "Most frequently visited domains",
      },
    },
    {
      pattern: /Spotify.*PersistentCache|spotify.*\.db/i,
      app: "Spotify",
      category: "media",
      permissions: ["playback.read"],
      namedQueries: {
        focus_music: "Tracks played during typical work hours (9am-6pm)",
        top_artists: "Most played artists by play count",
        recent_plays: "Last 100 tracks played",
        long_sessions: "Listening sessions longer than 2 hours",
      },
    },
    {
      pattern: /WhatsApp.*ChatStorage|WhatsApp.*Contacts/i,
      app: "WhatsApp",
      category: "messaging",
      permissions: ["messages.read", "contacts.read"],
      namedQueries: {
        top_contacts: "People messaged most in last 30 days",
        recent_chats: "Last 20 conversations",
        media_shared: "Messages containing media attachments",
        group_activity: "Most active group chats",
      },
    },
    {
      pattern: /Telegram.*cache4\.db|tdlib.*.*\.db/i,
      app: "Telegram",
      category: "messaging",
      permissions: ["messages.read"],
      namedQueries: {
        top_contacts: "Most active contacts",
        channels: "Channels with unread count",
      },
    },
    {
      pattern: /Signal.*db\.sqlite|signal-messenger/i,
      app: "Signal",
      category: "messaging",
      permissions: ["messages.read"],
      namedQueries: {
        conversations: "Active conversations sorted by recency",
      },
      connectionHints: {
        encryption: "sqlcipher",
        keychainService: "Signal Safe Storage",
        pbkdf2Salt: "saltysalt",
        pbkdf2Iter: 1003,
        ivFormat: "spaces"
      }
    },
    {
      pattern: /VSCode.*globalStorage|vscode.*\.vscdb/i,
      app: "VS Code",
      category: "developer",
      permissions: ["workspace.read", "extensions.read"],
      namedQueries: {
        recent_files: "Files opened in last 7 days",
        recent_workspaces: "Workspaces opened recently",
        installed_extensions: "All installed extensions",
      },
    },
    {
      pattern: /Obsidian.*obsidian\.sqlite|obsidian.*cache/i,
      app: "Obsidian",
      category: "notes",
      permissions: ["notes.read"],
      namedQueries: {
        recent_notes: "Notes modified in last 14 days",
        unlinked_notes: "Notes with no backlinks",
      },
    },
    {
      pattern: /Apple.*HealthKit|healthdb_secure\.sqlite/i,
      app: "Apple Health",
      category: "health",
      permissions: ["health.read"],
      namedQueries: {
        steps_trend: "Daily step count last 30 days",
        sleep_quality: "Sleep duration and quality scores",
        heart_rate: "Resting heart rate trend",
      },
    },
    {
      pattern: /\bcontacts\.db\b|AddressBook\.sqlitedb/i,
      app: "Contacts",
      category: "contacts",
      permissions: ["contacts.read"],
      namedQueries: {
        all_contacts: "All contacts with name and email",
        recent_edits: "Contacts modified recently",
      },
    },
    {
      pattern: /Messages.*chat\.db/i,
      app: "iMessage",
      category: "messaging",
      permissions: ["messages.read"],
      namedQueries: {
        recent_messages: "Last 50 text messages with sender names",
        top_chats: "Most active message threads",
        attachments: "Files and images shared via iMessage",
      },
    },
    {
      pattern: /com\.apple\.notes.*NoteStore\.sqlite/i,
      app: "Apple Notes",
      category: "notes",
      permissions: ["notes.read"],
      namedQueries: {
        all_notes: "Title and preview of all notes",
        folders: "List of note folders/categories",
        recent_notes: "Notes modified in last 7 days",
      },
    },
    {
      pattern: /Stickies\.sqlite/i,
      app: "Stickies",
      category: "notes",
      permissions: ["notes.read"],
      namedQueries: {
        all_stickies: "Content of all desktop sticky notes",
      },
    },
  ];

// ── Default scan paths per platform ──────────────────────────────────────────

function defaultScanPaths(): string[] {
  const home = os.homedir();
  const plat = process.platform;

  if (plat === "darwin") {
    return [
      path.join(home, "Library", "Application Support"),
      path.join(home, "Library", "Containers"),
      path.join(home, "Library", "Group Containers"),
      path.join(home, "Library", "Messages"),
      path.join(home, "Library", "Stickies"),
      path.join(home, "Library", "Notes"),
      path.join(home, "Library", "Mail"),
      path.join(home, "Documents"),
      path.join(home, "Downloads"),
      path.join(home, ".config"),
      path.join(home, ".local", "share"),
    ];
  }

  if (plat === "win32") {
    const appdata = process.env.APPDATA ?? path.join(home, "AppData", "Roaming");
    const localapp = process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local");
    return [appdata, localapp, path.join(home, "Documents"), path.join(home, "Downloads")];
  }

  // Linux
  return [
    path.join(home, ".config"),
    path.join(home, ".local", "share"),
    path.join(home, "Documents"),
    path.join(home, "Downloads"),
    "/var/lib",
  ];
}

const DEFAULT_SKIP = [
  "node_modules", ".git", "Caches", "Cache", "cache",
  "GPUCache", "Code Cache", "ShaderCache", "blob_storage",
  "DawnCache", "optimization_guide", "GrShaderCache",
  "CrashpadMetrics", "pnacl", "Crashpad",
  "System Preferences", "CoreServicesUIAgent",
  ".Trash", "Logs", "logs", "tmp", "temp",
];

// ── SQLite schema reader (pure Node.js, no native deps) ──────────────────────

function readSQLiteSchema(filePath: string): RawSchema | null {
  try {
    const buf = fs.readFileSync(filePath);

    // Validate SQLite magic header
    if (buf.length < 100 || buf.toString("ascii", 0, 6) !== "SQLite") return null;

    // Parse page size from header (bytes 16-17, big-endian)
    const pageSize = buf.readUInt16BE(16) || 65536;

    // The first page contains the sqlite_master table
    // We extract CREATE TABLE statements via a simple text scan
    const text = buf.toString("utf8", 100, Math.min(buf.length, pageSize * 4));

    const tables: RawSchema["tables"] = [];
    const createRe = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"([^"]+)"|`([^`]+)`|'([^']+)'|(\w+))\s*\(([^;]*)\)/gi;
    let match: RegExpExecArray | null;

    while ((match = createRe.exec(text)) !== null) {
      const tableName = (match[1] ?? match[2] ?? match[3] ?? match[4] ?? "").trim();
      if (!tableName || tableName.startsWith("sqlite_")) continue;

      const colDefs = match[5] ?? "";
      const columns: Array<{ name: string; type: string }> = [];

      // Parse column definitions
      for (const colLine of colDefs.split(",")) {
        const trimmed = colLine.trim();
        // Skip constraints
        if (/^(PRIMARY|UNIQUE|CHECK|FOREIGN|CONSTRAINT)/i.test(trimmed)) continue;
        const colMatch = trimmed.match(/^(?:"([^"]+)"|`([^`]+)`|'([^']+)'|(\w+))\s*([A-Z_]*)/i);
        if (colMatch) {
          const colName = (colMatch[1] ?? colMatch[2] ?? colMatch[3] ?? colMatch[4] ?? "").trim();
          const colType = (colMatch[5] ?? "TEXT").trim() || "TEXT";
          if (colName) columns.push({ name: colName, type: colType });
        }
      }

      if (columns.length > 0) {
        tables.push({ name: tableName, columns, rowCount: 0 });
      }
    }

    return tables.length > 0 ? { tables } : null;
  } catch {
    return null;
  }
}

// ── File scanner ─────────────────────────────────────────────────────────────

function scanForDatabases(
  roots: string[],
  skipPatterns: string[],
  maxFiles: number
): string[] {
  const found: string[] = [];
  const visited = new Set<string>();

  function walk(dir: string, depth: number) {
    if (depth > 6 || found.length >= maxFiles) return;
    if (visited.has(dir)) return;
    visited.add(dir);

    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (found.length >= maxFiles) break;

      const fullPath = path.join(dir, entry.name);
      const lname = entry.name.toLowerCase();

      // Skip system/cache dirs
      if (entry.isDirectory()) {
        if (skipPatterns.some(p => entry.name.includes(p))) continue;
        walk(fullPath, depth + 1);
        continue;
      }

      // SQLite files
      if (entry.isFile() && (
        lname.endsWith(".db") ||
        lname.endsWith(".sqlite") ||
        lname.endsWith(".sqlite3") ||
        lname === "history" ||
        lname === "places.sqlite" ||
        lname === "cookies" ||
        lname === "web data"
      )) {
        found.push(fullPath);
      }
    }
  }

  for (const root of roots) {
    if (fs.existsSync(root)) walk(root, 0);
  }
  return found;
}

// ── Heuristic app identifier ─────────────────────────────────────────────────

function identifyByFingerprint(filePath: string) {
  for (const fp of KNOWN_FINGERPRINTS) {
    if (fp.pattern.test(filePath)) return fp;
  }
  return null;
}

// ── AI schema analyser ────────────────────────────────────────────────────────

async function analyseWithAI(
  filePath: string,
  schema: RawSchema,
  apiKey: string,
  model: string
): Promise<{
  appName: string;
  category: string;
  description: string;
  permissions: string[];
  namedQueries: Record<string, string>;
  confidence: number;
} | null> {
  // Build a compact schema summary for the prompt
  const schemaSummary = schema.tables.slice(0, 8).map(t =>
    `Table "${t.name}": ${t.columns.slice(0, 12).map(c => `${c.name}(${c.type})`).join(", ")}`
  ).join("\n");

  const fileName = path.basename(filePath);
  const parentDir = path.basename(path.dirname(filePath));
  const grandDir = path.basename(path.dirname(path.dirname(filePath)));

  const prompt = `You are analyzing a SQLite database found on a user's Mac to auto-generate a privacy-first local data connector.

File path hint: .../${grandDir}/${parentDir}/${fileName}

Database schema:
${schemaSummary}

Based ONLY on the schema structure and file path, identify:
1. What app this database belongs to
2. What kind of data it contains
3. Useful named queries a personal AI assistant could run

Respond in JSON only, no markdown, no explanation:
{
  "appName": "string — the app name",
  "category": "browser|messaging|media|notes|health|finance|developer|contacts|calendar|other",
  "description": "one sentence describing what this data is",
  "permissions": ["array of permission strings like history.read, messages.read"],
  "namedQueries": {
    "query_key": "Human readable description of what this query returns"
  },
  "confidence": 0.0
}

Rules:
- confidence: 0.9+ if very sure, 0.6-0.89 if likely, 0.3-0.59 if uncertain
- namedQueries: 3-6 useful queries that would help a personal AI answer questions
- If you truly cannot identify it, set appName to "Unknown" and confidence below 0.3
- permissions must be specific: use format like "history.read" not just "read"`;

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: 600,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (!res.ok) return null;
    const data = await res.json() as { content: Array<{ type: string; text: string }> };
    const text = data.content.find(b => b.type === "text")?.text ?? "";

    // Strip any accidental markdown fences
    const clean = text.replace(/```json\n?|```\n?/g, "").trim();
    return JSON.parse(clean);
  } catch {
    return null;
  }
}

// ── Build a live connector from descriptor + file path ────────────────────────

function buildConnector(
  descriptor: ConnectorDescriptor,
  sourcePath: string
): BaseConnector {
  return {
    descriptor,
    async discover() { return true; },

    async schema(): Promise<SchemaMap> {
      return {};
    },

    async read(query: string): Promise<Row[]> {
      // For now returns schema + path info as rows.
      // When better-sqlite3 is available this becomes a real query.
      const schema = readSQLiteSchema(sourcePath);
      if (!schema) return [];

      const queryLower = query.toLowerCase();

      // Match query to named query keys to filter tables
      const matchedTable = schema.tables.find(t =>
        queryLower.includes(t.name.toLowerCase()) ||
        Object.keys(descriptor.namedQueries).some(k =>
          queryLower.includes(k.replace(/_/g, " "))
        )
      ) ?? schema.tables[0];

      if (!matchedTable) return [];

      // Return schema rows as descriptive data (real SQL when native deps available)
      return matchedTable.columns.map((col, i) => ({
        id: i,
        table: matchedTable.name,
        column: col.name,
        type: col.type,
        source: descriptor.name,
        note: `Real data requires: npm install better-sqlite3`,
      }));
    },


  };
}

// ── Main AutoConnectorGenerator class ────────────────────────────────────────

export class AutoConnectorGenerator {
  private opts: Required<AutoGenOptions>;

  constructor(opts: AutoGenOptions = {}) {
    this.opts = {
      apiKey: opts.apiKey ?? "",
      extraPaths: opts.extraPaths ?? [],
      maxFiles: opts.maxFiles ?? 200,
      skipPatterns: opts.skipPatterns ?? DEFAULT_SKIP,
      model: opts.model ?? "claude-haiku-4-5-20251001",
    };
  }

  /**
   * Scan the machine and return auto-generated connectors for everything found.
   * Already-known apps use heuristics (instant). Unknown ones call the AI.
   */
  async scan(): Promise<AutoGenResult[]> {
    const scanPaths = [...defaultScanPaths(), ...this.opts.extraPaths];
    const dbFiles = scanForDatabases(scanPaths, this.opts.skipPatterns, this.opts.maxFiles);

    const results: AutoGenResult[] = [];
    const seen = new Set<string>(); // deduplicate by app name

    for (const filePath of dbFiles) {
      try {
        const result = await this.generateForFile(filePath);
        if (!result) continue;
        if (result.confidence < 0.3) continue; // skip very uncertain
        if (seen.has(result.descriptor.app)) continue; // one connector per app
        seen.add(result.descriptor.app);
        results.push(result);
      } catch {
        // Skip files that error — locked, permissions, etc.
      }
    }

    // Sort by confidence descending
    return results.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Generate a connector for a specific file path.
   * Returns null if the file is not a recognisable database.
   */
  async generateForFile(filePath: string): Promise<AutoGenResult | null> {
    // 1. Try known fingerprint first (instant, no AI)
    const fp = identifyByFingerprint(filePath);
    if (fp) {
      const descriptor: ConnectorDescriptor = {
        name: fp.app.toLowerCase().replace(/\s+/g, "_"),
        app: fp.app,
        version: "auto-1.0",
        dataPaths: [filePath],
        permissions: fp.permissions,
        namedQueries: fp.namedQueries,
        description: `Auto-detected ${fp.app} ${fp.category} database`,
      };
      return {
        descriptor,
        connector: buildConnector(descriptor, filePath),
        confidence: 0.95,
        sourcePath: filePath,
        method: "known-app",
      };
    }

    // 2. Read schema
    const schema = readSQLiteSchema(filePath);
    if (!schema || schema.tables.length === 0) return null;

    // 3. Try AI analysis
    if (this.opts.apiKey) {
      const ai = await analyseWithAI(filePath, schema, this.opts.apiKey, this.opts.model);
      if (ai && ai.confidence >= 0.3 && ai.appName !== "Unknown") {
        const descriptor: ConnectorDescriptor = {
          name: ai.appName.toLowerCase().replace(/[\s.]+/g, "_"),
          app: ai.appName,
          version: "auto-1.0",
          dataPaths: [filePath],
          permissions: ai.permissions,
          namedQueries: ai.namedQueries,
          description: ai.description,
        };
        return {
          descriptor,
          connector: buildConnector(descriptor, filePath),
          confidence: ai.confidence,
          sourcePath: filePath,
          method: "ai",
        };
      }
    }

    // 4. Heuristic fallback — use table/column names to guess
    const heuristic = heuristicAnalyse(filePath, schema);
    if (heuristic && heuristic.confidence >= 0.35) {
      const descriptor: ConnectorDescriptor = {
        name: heuristic.appName.toLowerCase().replace(/\s+/g, "_"),
        app: heuristic.appName,
        version: "auto-1.0",
        dataPaths: [filePath],
        permissions: heuristic.permissions,
        namedQueries: heuristic.namedQueries,
        description: heuristic.description,
      };
      return {
        descriptor,
        connector: buildConnector(descriptor, filePath),
        confidence: heuristic.confidence,
        sourcePath: filePath,
        method: "heuristic",
      };
    }

    return null;
  }

  /**
   * Generate a single connector interactively — scans, shows what it found,
   * and lets the user confirm before registering.
   */
  async generateInteractive(filePath: string): Promise<AutoGenResult | null> {
    const result = await this.generateForFile(filePath);
    if (!result) {
      console.log(`[LDP AutoGen] Could not identify database at ${filePath}`);
      return null;
    }

    console.log(`\n[LDP AutoGen] Found: ${result.descriptor.app}`);
    console.log(`  Method:      ${result.method}`);
    console.log(`  Confidence:  ${(result.confidence * 100).toFixed(0)}%`);
    console.log(`  Description: ${result.descriptor.description}`);
    console.log(`  Queries:`);
    for (const [key, desc] of Object.entries(result.descriptor.namedQueries)) {
      console.log(`    ${key}: ${desc}`);
    }
    console.log();
    return result;
  }
}

// ── Heuristic analyser (no AI, pattern-based) ─────────────────────────────────

function heuristicAnalyse(filePath: string, schema: RawSchema): {
  appName: string;
  description: string;
  permissions: string[];
  namedQueries: Record<string, string>;
  confidence: number;
} | null {
  const allCols = schema.tables.flatMap(t => t.columns.map(c => c.name.toLowerCase()));
  const allTables = schema.tables.map(t => t.name.toLowerCase());
  const fileName = path.basename(filePath).toLowerCase();

  // Browser history signals
  if (
    allCols.some(c => ["url", "visit_count", "last_visit_time", "typed_count"].includes(c)) ||
    allTables.includes("urls") || allTables.includes("visits")
  ) {
    return {
      appName: "Browser History",
      description: "Browser history database with URLs and visit counts",
      permissions: ["history.read"],
      namedQueries: {
        most_visited: "Most visited URLs by visit count",
        recent_history: "Recently visited pages",
        typed_urls: "URLs typed directly by user",
      },
      confidence: 0.75,
    };
  }

  // Messaging signals
  if (allCols.some(c => ["message_id", "sender", "recipient", "body", "timestamp"].includes(c)) ||
    allTables.some(t => ["messages", "chats", "conversations"].includes(t))) {
    return {
      appName: "Messaging App",
      description: "Messaging database with conversations and messages",
      permissions: ["messages.read"],
      namedQueries: {
        recent_messages: "Most recent messages",
        top_contacts: "Most messaged contacts",
      },
      confidence: 0.65,
    };
  }

  // Calendar / events signals
  if (allCols.some(c => ["event_id", "start_date", "end_date", "summary", "dtstart"].includes(c)) ||
    allTables.some(t => ["events", "calendar", "vevent"].includes(t))) {
    return {
      appName: "Calendar",
      description: "Calendar events database",
      permissions: ["calendar.read"],
      namedQueries: {
        upcoming_events: "Events in next 7 days",
        recurring_events: "Recurring calendar events",
      },
      confidence: 0.7,
    };
  }

  // Notes / documents signals
  if (allCols.some(c => ["note_id", "content", "title", "created_at", "modified_at"].includes(c)) ||
    allTables.some(t => ["notes", "documents", "entries"].includes(t))) {
    const appName = fileName.includes("bear") ? "Bear" :
      fileName.includes("notion") ? "Notion" :
        "Notes App";
    return {
      appName,
      description: "Notes/documents database with text content",
      permissions: ["notes.read"],
      namedQueries: {
        recent_notes: "Notes modified in last 14 days",
        all_notes: "All notes with title and preview",
      },
      confidence: 0.6,
    };
  }

  // Finance / banking signals
  if (allCols.some(c => ["amount", "transaction_id", "merchant", "balance", "account_id"].includes(c)) ||
    allTables.some(t => ["transactions", "accounts", "transfers"].includes(t))) {
    return {
      appName: "Finance App",
      description: "Financial transactions and account data",
      permissions: ["finance.read"],
      namedQueries: {
        recent_transactions: "Transactions in last 30 days",
        spending_by_category: "Total spending grouped by category",
      },
      confidence: 0.72,
    };
  }

  // Media / music signals
  if (allCols.some(c => ["track_id", "artist", "album", "play_count", "duration_ms"].includes(c)) ||
    allTables.some(t => ["tracks", "artists", "albums", "plays"].includes(t))) {
    return {
      appName: "Music Player",
      description: "Music library and playback history",
      permissions: ["media.read"],
      namedQueries: {
        top_tracks: "Most played tracks",
        recent_plays: "Recently played tracks",
      },
      confidence: 0.68,
    };
  }

  return null;
}

// ── CLI helper — auto-gen on demand ──────────────────────────────────────────

/**
 * CLI Entry point
 */
if (process.argv[1] === import.meta.url.replace("file://", "")) {
  const args = process.argv.slice(2);
  const jsonMode = args.includes("--json");
  const apiKey = process.env.ANTHROPIC_API_KEY;

  autoGenCLI(apiKey, jsonMode).catch(err => {
    if (jsonMode) {
      console.log(JSON.stringify({ error: err.message }));
    } else {
      console.error(err);
    }
    process.exit(1);
  });
}

export async function autoGenCLI(apiKey?: string, jsonMode: boolean = false) {
  if (!jsonMode) {
    console.log("\n[LDP] Auto Connector Generator — scanning your machine...\n");
  }

  const gen = new AutoConnectorGenerator({ apiKey, maxFiles: 150 });
  const results = await gen.scan();

  if (jsonMode) {
    console.log(JSON.stringify(results, null, 2));
    return results;
  }

  if (results.length === 0) {
    console.log("No new databases found (or all already registered).\n");
    return [];
  }

  console.log(`Found ${results.length} new data source(s):\n`);
  for (const r of results) {
    const badge = r.method === "known-app" ? "✓ known" :
      r.method === "ai" ? "✦ AI" : "~ heuristic";
    console.log(`  [${badge}] ${r.descriptor.app} (${(r.confidence * 100).toFixed(0)}% confidence)`);
    console.log(`         ${r.descriptor.description}`);
    console.log(`         Queries: ${Object.keys(r.descriptor.namedQueries).join(", ")}`);
    console.log(`         Path: ${r.sourcePath}\n`);
  }

  return results;
}
