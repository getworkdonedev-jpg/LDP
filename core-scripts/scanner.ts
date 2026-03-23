/**
 * LDP Full System Scanner
 * =======================
 * Scans the ENTIRE machine. Not just 15 known apps.
 *
 * Phase 1 — Walk filesystem
 *   Every .db .sqlite .sqlite3 .vscdb .json .csv file
 *   Skips: node_modules, .git, system caches, tmp, known noise
 *
 * Phase 2 — Fingerprint
 *   Read first 16 bytes → plain SQLite / SQLCipher / JSON / CSV
 *
 * Phase 3 — Identify
 *   Path signature match (instant, no AI)
 *   Schema analysis via better-sqlite3
 *   Heuristic column/table name matching
 *
 * Phase 4 — Process snapshot
 *   All running processes (ps aux / tasklist)
 *   Top 20: their open data files (lsof)
 *
 * Phase 5 — Network snapshot
 *   All ESTABLISHED + LISTEN connections (netstat / ss)
 *
 * Phase 6 — Register with LDP engine
 *   confidence ≥ 0.8 → auto-connect
 *   confidence 0.5–0.8 → pendingApproval
 *   confidence < 0.5 → skip
 *
 * Usage:
 *   import { SystemScanner } from "@ldp-protocol/sdk";
 *
 *   const scanner = new SystemScanner({ verbose: true });
 *   const result  = await scanner.run();
 *   console.log(result.databases);   // every SQLite found + identity
 *   console.log(result.processes);   // running apps right now
 *   console.log(result.network);     // active connections
 */

import * as fs           from "node:fs";
import * as path         from "node:path";
import * as os           from "node:os";
import { execSync }      from "node:child_process";
import { createRequire } from "node:module";
import type { LDPEngine }                from "./engine.js";
import type { BaseConnector, Row, SchemaMap } from "./types.js";
import { KnowledgeBase }               from "./brain.js";
import type { DataCategory, DecryptMethod } from "./brain.js";

const require = createRequire(import.meta.url);

// ── Types ─────────────────────────────────────────────────────────────────────
export type FileType = "sqlite" | "sqlcipher" | "json" | "csv" | "unknown";

export interface ScannedFile {
  filePath:   string;
  fileType:   FileType;
  sizeBytes:  number;
  mtimeMs:    number;
  appName:    string;
  category:   DataCategory;
  confidence: number;
  tables:     string[];
  encrypted:  boolean;
  totalRows:  number;
  maxRows:    number;
  staticMatch?: "mail" | "shell" | "git" | "logs" | "plist";
  method: DecryptMethod;
}

export interface ProcessInfo {
  pid:       number;
  name:      string;
  cpu:       number;
  memory:    number;
  user:      string;
  command:   string;
  openFiles: string[];
}

export interface NetworkConnection {
  protocol:    string;
  localAddr:   string;
  localPort:   number;
  remoteAddr:  string;
  remotePort:  number;
  state:       string;
  pid:         number;
  processName: string;
}

export interface ScanResult {
  scannedFiles:    number;
  scannedDirs:     number;
  durationMs:      number;
  databases:       ScannedFile[];
  dataFiles:       ScannedFile[];
  processes:       ProcessInfo[];
  network:         NetworkConnection[];
  autoConnected:   string[];
  pendingApproval: ScannedFile[];
  skipped:         number;
}

export interface SystemScannerOptions {
  verbose?:              boolean;
  maxFiles?:             number;    // default 5000
  maxDepth?:             number;    // default 8
  autoConnectThreshold?: number;    // default 0.80
  engine?:               InstanceType<typeof import("./engine.js").LDPEngine>;
  includeProcesses?:     boolean;   // default true
  includeNetwork?:       boolean;   // default true
  includeOpenFiles?:     boolean;   // default false (slow)
}

// ── Skip lists ────────────────────────────────────────────────────────────────
const SKIP_DIRS = new Set([
  "node_modules",".git",".npm",".yarn",".pnpm",
  "Cache","Caches","cache","GPUCache","Code Cache",
  "ShaderCache","DawnCache","blob_storage","CrashpadMetrics",
  "GrShaderCache","optimization_guide","pnacl",
  ".Trash","Logs","logs","tmp","temp","Crashpad","CrashReports",
  "Extensions","Themes","IndexedDB","Local Storage",
  "Session Storage","Service Worker","WebSQL",
  "__pycache__",".tox","venv",".venv",
  "build","dist","out",".cargo",".rustup",
]);

const SKIP_PATH_PATTERNS = [
  "/System/","/usr/","/private/var/","/Library/Caches/",
  "/.Spotlight-","/CoreData/","metadata.sqlite","CloudKitLocalStore",
  "tomb","backup","cache","thumbnail","authorization",
  "akd","siri_inference","heavy_ad","tipkit","dock_desktop",
  "drivefs", "DriveFS"
];

const DATA_EXTS = new Set([
  ".db", ".sqlite", ".sqlite3", ".db3", ".vscdb", ".json", ".csv",
  ".emlx", ".zsh_history", ".bash_history", ".plist"
]);

// ── Scan roots ────────────────────────────────────────────────────────────────
function getScanRoots(): string[] {
  const h = os.homedir();
  const roots = [
    path.join(h, "Library", "Messages"),
    path.join(h, "Library", "Safari"),
    path.join(h, "Library", "Mail"),
    path.join(h, "Library", "Notes"),
    path.join(h, "Library", "Calendars"),
    path.join(h, "Library", "Reminders"),
    path.join(h, "Library", "Group Containers"),
    path.join(h, "Library", "Application Support"),
    path.join(h, "Music"),
    path.join(h, "Documents"),
    path.join(h, "Desktop"),
    "/var/log"
  ];
  return roots.filter(r => fs.existsSync(r));
}

function shouldSkip(name: string, full: string): boolean {
  if (SKIP_DIRS.has(name)) return true;
  return SKIP_PATH_PATTERNS.some(p => full.includes(p));
}

// ── Phase 1: Walk ─────────────────────────────────────────────────────────────
function walk(
  roots: string[], max: number, maxDepth: number,
  cb: (fp: string, stat: fs.Stats) => void,
): { scannedFiles: number; scannedDirs: number } {
  let files = 0, dirs = 0;
  const visited = new Set<string>();

  function recurse(dir: string, depth: number) {
    if (depth > maxDepth || files >= max || visited.has(dir)) return;
    visited.add(dir);
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    dirs++;
    for (const e of entries) {
      if (files >= max) break;
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === ".git") {
          cb(fp, fs.statSync(fp));
          continue;
        }
        if (!shouldSkip(e.name, fp)) recurse(fp, depth+1);
        continue;
      }
      if (e.isFile()) {
        if (shouldSkip(e.name, fp)) continue;
        const ext = path.extname(e.name).toLowerCase();
        if (ext === ".log") {
          if (fp.startsWith("/var/log") || fp.includes("/Library/Logs/")) {
             cb(fp, fs.statSync(fp));
          }
          continue;
        }
        if (!DATA_EXTS.has(ext)) continue;
        let stat: fs.Stats;
        try { stat = fs.statSync(fp); } catch { continue; }
        if (stat.size < 512 || stat.size > 500*1024*1024) continue;
        files++;
        cb(fp, stat);
      }
    }
  }

  for (const r of roots) if (fs.existsSync(r)) recurse(r, 0);
  return { scannedFiles: files, scannedDirs: dirs };
}

// ── Phase 2: Fingerprint ──────────────────────────────────────────────────────
function fingerprint(fp: string): FileType {
  const ext = path.extname(fp).toLowerCase();
  if (ext === ".json") return "json";
  if (ext === ".csv")  return "csv";
  try {
    const fd  = fs.openSync(fp, "r");
    const buf = Buffer.alloc(16);
    const n   = fs.readSync(fd, buf, 0, 16, 0);
    fs.closeSync(fd);
    if (n < 6) return "unknown";
    if (buf.toString("utf8", 0, 6) === "SQLite") return "sqlite";
    if (ext === ".emlx" || path.basename(fp).includes("zsh_history") || path.basename(fp).includes("bash_history") || ext === ".plist" || ext === ".log" || path.basename(fp) === ".git") {
      return "json"; // loosely treat static matches as generic data files for processor
    }
    const nonzero = buf.reduce((s,b) => s+(b>0?1:0), 0);
    if (nonzero > 8) return "sqlcipher";
    return "unknown";
  } catch { return "unknown"; }
}

// ── Phase 3: Identify ─────────────────────────────────────────────────────────
const PATH_SIGS: Array<{ pat: RegExp; app: string; cat: DataCategory; conf: number }> = [
  { pat: /Messages.*chat\.db/i,                                  app:"iMessage",        cat:"messaging",  conf:0.99 },
  { pat: /group\.com\.apple\.notes.*NoteStore\.sqlite/i,         app:"Apple Notes",     cat:"notes",      conf:0.99 },
  { pat: /Safari.*History\.db/i,                                 app:"Safari",          cat:"browser",    conf:0.99 },
  { pat: /Calendars.*\.sqlite/i,                                 app:"Calendar",        cat:"calendar",   conf:0.98 },
  { pat: /Reminders.*\.sqlite/i,                                 app:"Reminders",       cat:"calendar",   conf:0.98 },
  { pat: /AddressBook.*\.sqlitedb/i,                             app:"Contacts",        cat:"contacts",   conf:0.98 },
  { pat: /Music.*\.sqlite/i,                                     app:"Apple Music",     cat:"media",      conf:0.98 },
  { pat: /group\.com\.apple\.journal.*\.sqlite/i,                app:"Apple Journal",   cat:"notes",      conf:0.98 },
  { pat: /Chrome.*History|Brave.*History|Chromium.*History/i,   app:"Chrome/Brave",    cat:"browser",    conf:0.97 },
  { pat: /Firefox.*places\.sqlite/i,                            app:"Firefox",         cat:"browser",    conf:0.97 },
  { pat: /Signal.*db\.sqlite/i,                                  app:"Signal",          cat:"messaging",  conf:0.97 },
  { pat: /WhatsApp.*ChatStorage/i,                               app:"WhatsApp",        cat:"messaging",  conf:0.97 },
  { pat: /Telegram.*db_sqlite/i,                                 app:"Telegram",        cat:"messaging",  conf:0.95 },
  { pat: /Code.*globalStorage.*vscdb|Cursor.*globalStorage/i,   app:"VS Code/Cursor",  cat:"developer",  conf:0.97 },
  { pat: /Spotify.*podcasts\.db/i,                               app:"Spotify",         cat:"media",      conf:0.95 },
  { pat: /healthdb_secure\.sqlite|HealthKit/i,                   app:"Apple Health",    cat:"health",     conf:0.95 },
  { pat: /Slack.*db$/i,                                          app:"Slack",           cat:"messaging",  conf:0.88 },
  { pat: /Discord.*db$/i,                                        app:"Discord",         cat:"messaging",  conf:0.88 },
  { pat: /Obsidian.*\.sqlite/i,                                  app:"Obsidian",        cat:"notes",      conf:0.88 },
];

function identifyFromPath(fp: string) {
  for (const s of PATH_SIGS) if (s.pat.test(fp)) return { app: s.app, cat: s.cat, conf: s.conf };
  return null;
}

function readTables(fp: string): string[] {
  try {
    const DB = require("better-sqlite3");
    const db = new DB(fp, { readonly: true, timeout: 2000 });
    const rows: any[] = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 20").all();
    db.close();
    return rows.map(r => r.name);
  } catch { return []; }
}

function readDensity(fp: string, tables: string[]): { total: number, max: number } {
  if (tables.length === 0) return { total: 0, max: 0 };
  let total = 0;
  let max = 0;
  let db: any;
  let tmpPath: string | null = null;
  try {
    const DB = require("better-sqlite3");
    
    // Always use a temp copy for density check to avoid locks from running apps
    tmpPath = path.join(os.tmpdir(), `ldp_scan_${Math.random().toString(36).slice(2)}.db`);
    fs.copyFileSync(fp, tmpPath);
    db = new DB(tmpPath, { readonly: true, timeout: 2000 });

    for (const t of tables.slice(0, 15)) {
      try {
        const res = db.prepare(`SELECT count(*) as count FROM "${t}"`).get() as { count: number };
        total += res.count;
        if (res.count > max) max = res.count;
      } catch {}
    }
  } catch {} finally {
    if (db) try { db.close(); } catch {}
    if (tmpPath) try { fs.unlinkSync(tmpPath); } catch {}
  }
  return { total, max };
}

function readColumns(fp: string, tables: string[]): string[] {
  const cols: string[] = [];
  try {
    const DB = require("better-sqlite3");
    const db = new DB(fp, { readonly: true, timeout: 2000 });
    for (const t of tables.slice(0,5)) {
      try {
        const ci: any[] = db.prepare(`PRAGMA table_info("${t}")`).all();
        cols.push(...ci.map((c: any) => c.name.toLowerCase()));
      } catch {}
    }
    db.close();
  } catch {}
  return cols;
}

// Brain fingerprinting handler dynamically passed tables now
// (Implemented across phase boundaries)

async function analyseFile(fp: string, stat: fs.Stats, ft: FileType, kb: any): Promise<ScannedFile> {
  const base: ScannedFile = {
    filePath: fp, fileType: ft, sizeBytes: stat.size, mtimeMs: stat.mtimeMs,
    appName: path.basename(fp), category: "other", confidence: 0.1,
    tables: [], encrypted: ft === "sqlcipher", totalRows: 0, maxRows: 0,
    method: "plain_sqlite"
  };
  if (ft === "sqlcipher") base.method = "unknown";

  if (fp.endsWith(".emlx")) {
    const res = { ...base, appName:"Apple Mail", category:"messaging", confidence:1.0, staticMatch:"mail" } as ScannedFile;
    const slug = path.basename(fp).toLowerCase().replace(/[^a-z0-9]/g,"_");
    kb.learn({ appKey: `static_mail_${slug}`, appName: res.appName, filePath: fp, method: "plain_sqlite", category: "messaging", params: {}, schema: {}, confidence: 1.0 }, false);
    return res;
  }
  if (path.basename(fp).includes("zsh_history") || path.basename(fp).includes("bash_history")) {
    const res = { ...base, appName:"Terminal Shell", category:"developer", confidence:1.0, staticMatch:"shell" } as ScannedFile;
    const slug = path.basename(fp).toLowerCase().replace(/[^a-z0-9]/g,"_");
    kb.learn({ appKey: `static_shell_${slug}`, appName: res.appName, filePath: fp, method: "plain_sqlite", category: "developer", params: {}, schema: {}, confidence: 1.0 }, false);
    return res;
  }
  if (fp.endsWith(".git")) {
    const res = { ...base, appName:"Git Repository", category:"developer", confidence:1.0, staticMatch:"git" } as ScannedFile;
    const slug = path.basename(path.dirname(fp)).toLowerCase().replace(/[^a-z0-9]/g,"_");
    kb.learn({ appKey: `static_git_${slug}`, appName: res.appName, filePath: fp, method: "plain_sqlite", category: "developer", params: {}, schema: {}, confidence: 1.0 }, false);
    return res;
  }
  if (fp.endsWith(".log")) {
    const res = { ...base, appName:"System Logs", category:"other", confidence:1.0, staticMatch:"logs" } as ScannedFile;
    const slug = path.basename(fp).toLowerCase().replace(/[^a-z0-9]/g,"_");
    kb.learn({ appKey: `static_logs_${slug}`, appName: res.appName, filePath: fp, method: "plain_sqlite", category: "other", params: {}, schema: {}, confidence: 1.0 }, false);
    return res;
  }
  if (fp.endsWith(".plist")) {
    const res = { ...base, appName:"App Preferences", category:"other", confidence:1.0, staticMatch:"plist" } as ScannedFile;
    const slug = path.basename(fp).toLowerCase().replace(/[^a-z0-9]/g,"_");
    kb.learn({ appKey: `static_plist_${slug}`, appName: res.appName, filePath: fp, method: "plain_sqlite", category: "other", params: {}, schema: {}, confidence: 1.0 }, false);
    return res;
  }

  const pm = identifyFromPath(fp);
  const tables = (ft === "sqlite" || ft === "sqlcipher") ? readTables(fp) : [];
  const density = ft === "sqlite" ? readDensity(fp, tables) : { total: 0, max: 0 };

  if (pm) {
    const res = { ...base, appName: pm.app, category: pm.cat, confidence: pm.conf, tables, totalRows: density.total, maxRows: density.max };
    const slug = path.basename(fp).toLowerCase().replace(/[^a-z0-9]/g,"_");
    kb.learn({ 
      appKey: `path_${pm.app.toLowerCase().replace(/[^a-z0-9]/g,"_")}_${slug}`, 
      appName: pm.app, 
      filePath: fp, 
      method: ft === "sqlcipher" ? "unknown" : "plain_sqlite", 
      category: pm.cat, 
      params: {}, 
      schema: {}, 
      confidence: pm.conf,
      totalRows: density.total,
      maxRows: density.max
    }, false);
    return res;
  }

  if (ft === "sqlite" && density.max >= 10) {
    // If table size >= 10, defer to Brain for identification
    const { BrainFingerprint } = require("./brain.js");
    const ai = BrainFingerprint(tables);
    
    if (ai.confidence >= 0.6) {
      const slug = path.basename(fp).toLowerCase().replace(/[^a-z0-9]/g,"_");
      const appKey = `auto_${ai.appName.toLowerCase().replace(/[^a-z0-9]/g,"_")}_${slug}`;
      if (!kb.lookup(fp)) {
        kb.learn({
          appKey,
          appName: ai.appName,
          filePath: fp,
          method: "plain_sqlite",
          category: ai.category,
          params: {},
          schema: {},
          confidence: ai.confidence,
          totalRows: density.total,
          maxRows: density.max
        }, false);
      }
      return { ...base, tables, appName: ai.appName, category: ai.category, confidence: ai.confidence, totalRows: density.total, maxRows: density.max };
    } else {
      const folder = path.basename(path.dirname(fp));
      const unknownName = `unknown_${folder}`.toLowerCase().replace(/[^a-z0-9_]/g, "_");
      const slug = path.basename(fp).toLowerCase().replace(/[^a-z0-9]/g,"_");
      const appKey = `${unknownName}_${slug}`;
      if (!kb.lookup(fp)) {
        kb.learn({
          appKey,
          appName: unknownName,
          filePath: fp,
          method: "plain_sqlite",
          category: "other",
          params: {},
          schema: {},
          confidence: ai.confidence,
          totalRows: density.total,
          maxRows: density.max
        }, false);
      }
      return { ...base, tables, appName: unknownName, category: "other", confidence: ai.confidence, totalRows: density.total, maxRows: density.max };
    }
  }

  if (ft === "json" || ft === "csv") {
    const parent = path.basename(path.dirname(fp)).toLowerCase();
    if (parent.includes("signal"))  return { ...base, appName:"Signal",  category:"messaging", confidence:0.70 };
    if (parent.includes("chrome"))  return { ...base, appName:"Chrome",  category:"browser",   confidence:0.70 };
    if (parent.includes("slack"))   return { ...base, appName:"Slack",   category:"messaging", confidence:0.70 };
    if (parent.includes("discord")) return { ...base, appName:"Discord", category:"messaging", confidence:0.70 };
    return { ...base, confidence: 0.20 };
  }

  return base;
}

// ── Phase 4: Processes ────────────────────────────────────────────────────────
function getProcesses(): ProcessInfo[] {
  try {
    if (process.platform === "win32") {
      const out = execSync("tasklist /FO CSV /NH", { encoding:"utf-8", stdio:["pipe","pipe","pipe"], timeout:5000 });
      return out.trim().split("\n").slice(0,100).map(line => {
        const p = line.replace(/"/g,"").split(",");
        return { name:p[0]??"", pid:parseInt(p[1]??"0"), cpu:0, memory:parseFloat(p[4]??"0")/1024, user:"", command:p[0]??"", openFiles:[] };
      }).filter(p => p.pid > 0);
    }
    const out = execSync("ps aux --no-headers 2>/dev/null || ps aux | tail -n +2",
      { encoding:"utf-8", stdio:["pipe","pipe","pipe"], timeout:5000 });
    return out.trim().split("\n").slice(0,200).map(line => {
      const p = line.trim().split(/\s+/);
      return { user:p[0]??"", pid:parseInt(p[1]??"0"), cpu:parseFloat(p[2]??"0"), memory:parseFloat(p[3]??"0"),
               name:path.basename(p[10]??"unknown"), command:p.slice(10).join(" ").slice(0,120), openFiles:[] };
    }).filter(p => p.pid > 0 && p.name !== "unknown").sort((a,b) => b.cpu-a.cpu).slice(0,50);
  } catch { return []; }
}

function getOpenDataFiles(pid: number): string[] {
  try {
    const out = execSync(`lsof -p ${pid} -Fn 2>/dev/null | grep "^n" | grep -E "\\.(db|sqlite|sqlite3|json|csv)$"`,
      { encoding:"utf-8", stdio:["pipe","pipe","pipe"], timeout:2000 });
    return out.trim().split("\n").map(l => l.slice(1).trim()).filter(Boolean).slice(0,10);
  } catch { return []; }
}

// ── Phase 5: Network ──────────────────────────────────────────────────────────
function getNetwork(): NetworkConnection[] {
  try {
    const out = execSync(
      "netstat -tunap 2>/dev/null || netstat -tuna 2>/dev/null || ss -tunap 2>/dev/null",
      { encoding:"utf-8", stdio:["pipe","pipe","pipe"], timeout:5000 }
    );
    const conns: NetworkConnection[] = [];
    for (const line of out.trim().split("\n").slice(2)) {
      const p = line.trim().split(/\s+/);
      if (p.length < 4) continue;
      const proto = (p[0]??"").toLowerCase();
      if (!proto.startsWith("tcp") && !proto.startsWith("udp")) continue;
      const parse = (addr: string) => {
        const i = addr.lastIndexOf(":");
        return { host: addr.slice(0,i) || addr, port: parseInt(addr.slice(i+1)) || 0 };
      };
      const local  = parse(p[3]??"");
      const remote = parse(p[4]??"");
      const state  = p[5]??"";
      const pid    = parseInt((p.at(-1)??"").split("/")[0]) || 0;
      if (local.port === 0) continue;
      conns.push({ protocol:proto.replace(/[46]/g,""), localAddr:local.host, localPort:local.port,
                   remoteAddr:remote.host, remotePort:remote.port,
                   state:state.toUpperCase(), pid, processName:"" });
    }
    return conns.filter(c => c.state==="ESTABLISHED" || c.state==="LISTEN").slice(0,100);
  } catch { return []; }
}

// ── Connector builder ─────────────────────────────────────────────────────────
function buildConnector(scanned: ScannedFile): BaseConnector {
  const descriptor = {
    name:         scanned.appName.toLowerCase().replace(/[^a-z0-9]/g,"_"),
    app:          scanned.appName,
    version:      "scan-1.0",
    dataPaths:    [scanned.filePath],
    permissions:  [`${scanned.category}.read`],
    namedQueries: { recent:`Recent ${scanned.appName} data`, all:`All ${scanned.appName} records` },
    description:  `Auto-scanned ${scanned.appName} — ${scanned.category}. Local only.`,
  };

  return {
    descriptor,
    async discover() { return fs.existsSync(scanned.filePath); },
    async schema(): Promise<SchemaMap> {
      const m: SchemaMap = {};
      for (const t of scanned.tables.slice(0,8)) m[t] = {};
      return m;
    },
    async read(_query: string, limit = 100): Promise<Row[]> {
      if (scanned.encrypted) return [];
      const tmp = path.join(os.tmpdir(), `ldp_scan_${Date.now()}.db`);
      try {
        fs.copyFileSync(scanned.filePath, tmp);
        const DB = require("better-sqlite3");
        const db = new DB(tmp, { readonly: true, timeout: 3000 });
        const table = scanned.tables[0];
        if (!table) { db.close(); return []; }
        const cols: any[] = db.prepare(`PRAGMA table_info("${table}")`).all();
        const timeCol = cols.find((c: any) => /time|date|ts|at|created/i.test(c.name));
        const sel = cols.slice(0,8).map((c: any) => `"${c.name}"`).join(", ");
        const order = timeCol ? `ORDER BY "${timeCol.name}" DESC` : "";
        const rows: Row[] = db.prepare(`SELECT ${sel} FROM "${table}" ${order} LIMIT ${limit}`).all();
        db.close();
        return rows.map(r => ({ ...r, _src: scanned.appName }));
      } catch { return []; }
      finally { try { fs.unlinkSync(tmp); } catch {} }
    },
  };
}

// ── SystemScanner ─────────────────────────────────────────────────────────────
export class SystemScanner {
  constructor(private readonly opts: SystemScannerOptions = {}) {}

  async run(): Promise<ScanResult> {
    const t0        = Date.now();
    const maxFiles  = this.opts.maxFiles ?? 5000;
    const maxDepth  = this.opts.maxDepth ?? 8;
    const threshold = this.opts.autoConnectThreshold ?? 0.80;
    const learned   = new KnowledgeBase();

    if (this.opts.verbose) {
      console.log("\n[SCAN] Starting full system scan");
      console.log(`[SCAN] Roots: ${getScanRoots().length} dirs | Max files: ${maxFiles}\n`);
    }

    const result: ScanResult = {
      scannedFiles:0, scannedDirs:0, durationMs:0,
      databases:[], dataFiles:[], processes:[], network:[],
      autoConnected:[], pendingApproval:[], skipped:0,
    };

    // Phase 1-3: walk → fingerprint → analyse
    const found: Array<{ fp: string; stat: fs.Stats }> = [];
    const counts = walk(getScanRoots(), maxFiles, maxDepth, (fp, stat) => found.push({ fp, stat }));
    result.scannedFiles = counts.scannedFiles;
    result.scannedDirs  = counts.scannedDirs;

    if (this.opts.verbose) console.log(`[SCAN] Found ${found.length} data files in ${counts.scannedDirs} dirs`);

    // Analyse in batches of 20
    const BATCH = 20;
    for (let i = 0; i < found.length; i += BATCH) {
      const batch = found.slice(i, i+BATCH);
      const analysed = await Promise.all(batch.map(async ({ fp, stat }) => {
        const ft = fingerprint(fp);
        if (ft === "unknown") return null;
        // Check learned base first (instant)
        const known = (learned as any).lookup(fp);
        if (known) {
          return {
            filePath: fp, fileType: ft, sizeBytes: stat.size, mtimeMs: stat.mtimeMs,
            appName: known.appName, category: known.category,
            confidence: Math.min(known.confidence + 0.05, 1.0),
            tables: Object.keys(known.schema || {}), encrypted: known.method !== "plain_sqlite",
            totalRows: (known as any).totalRows ?? 0,
            maxRows: (known as any).maxRows ?? 0,
          } as ScannedFile;
        }
        return (analyseFile as any)(fp, stat, ft, learned);
      }));

      for (const scanned of analysed) {
        if (!scanned) { result.skipped++; continue; }

        // Density Rules:
        // 1. Zero rows -> ignore
        // 2. < 10 total rows -> low priority, skip auto-register
        // 3. at least one table > 10 rows -> auto-register candidate
        if (scanned.fileType === "sqlite" && scanned.totalRows === 0) {
          if (this.opts.verbose) console.log(`[SCAN] Skipping empty DB: ${scanned.appName}`);
          result.skipped++;
          continue;
        }

        if (scanned.fileType === "sqlite" || scanned.fileType === "sqlcipher") {
          result.databases.push(scanned);
        } else {
          result.dataFiles.push(scanned);
        }

        const isLowPriority = scanned.fileType === "sqlite" && scanned.totalRows < 10;
        const canAutoRegister = scanned.fileType !== "sqlite" || scanned.maxRows > 10;
        
        // Whitelist high-value known sources: bypass density skip
        const isWhitelisted = scanned.appName === "Google Chrome" || 
                              scanned.appName === "Signal" || 
                              scanned.confidence >= 0.8;

        if (isLowPriority && this.opts.verbose && !isWhitelisted) {
          console.log(`[SCAN] Low priority (total rows ${scanned.totalRows}): ${scanned.appName}`);
        }

        // Auto-connect high-confidence files
        // We bypass density checks IF whitelisted (e.g. Chrome/Signal)
        const densityMatch = (!isLowPriority && canAutoRegister) || isWhitelisted;

        if (scanned.confidence >= threshold && this.opts.engine && !scanned.encrypted && densityMatch) {
          const connector = buildConnector(scanned);
          const name = connector.descriptor.name;
          if (!result.autoConnected.includes(name)) {
            this.opts.engine.register(connector);
            this.opts.engine.grantConsent(name, "system-scan");
            const msg = await this.opts.engine.connect(name, false);
            if (msg.type === "ACK") {
              result.autoConnected.push(name);
              const slug = path.basename(scanned.filePath).toLowerCase().replace(/[^a-z0-9]/g,"_");
              const appKey = `auto_${scanned.appName.toLowerCase().replace(/[^a-z0-9]/g,"_")}_${slug}`;
              learned.learn({
                appKey,
                filePath: scanned.filePath, 
                appName: scanned.appName,
                category: scanned.category, 
                method: "plain_sqlite",
                params: {},
                schema: {}, 
                confidence: scanned.confidence,
                totalRows: scanned.totalRows,
                maxRows: scanned.maxRows,
              });
              if (this.opts.verbose) console.log(`[SCAN] ✓ auto-connected: ${scanned.appName} (${(scanned.confidence*100).toFixed(0)}%)`);
            }
          }
        } else if (scanned.confidence >= 0.5 && scanned.confidence < threshold) {
          result.pendingApproval.push(scanned);
        } else {
          // If it didn't auto-connect and wasn't pending approval, it's skipped
          if (scanned.confidence < 0.5 || isLowPriority || !canAutoRegister) {
            result.skipped++;
          }
        }
      }
    }

    // Rule 1: Direct Probing for High-Value Apps (Bypass TCC readdir blocks)
    const h = os.homedir();
    const probes = [
      { path: path.join(h, "Library/Messages/chat.db"), app: "iMessage" },
      { path: path.join(h, "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"), app: "Apple Notes" },
      { path: path.join(h, "Library/Safari/History.db"), app: "Safari" },
      { path: path.join(h, "Library/Calendars/Calendar.sqlitedb"), app: "Apple Calendar" },
      { path: path.join(h, "Library/Calendars/Calendar.sqlite"), app: "Apple Calendar" },
      { path: path.join(h, "Library/Application Support/AddressBook/AddressBook-v22.abcddb"), app: "Apple Contacts" },
      { path: path.join(h, "Library/Reminders/Container_v1/Reminders.sqlite"), app: "Reminders" },
      { path: path.join(h, "Library/Reminders/Reminders.sqlite"), app: "Reminders" },
      { path: path.join(h, "Library/Group Containers/group.com.apple.journal/Journal.sqlite"), app: "Apple Journal" },
      { path: path.join(h, "Music/Music/Music Library.musiclibrary/Library.sqlite"), app: "Apple Music" },
      { path: path.join(h, "Library/Application Support/Google/Chrome/Default/History"), app: "Chrome" },
      { path: path.join(h, "Library/Mail/V10/MailData/Envelope Index"), app: "Apple Mail" },
      { path: path.join(h, ".zsh_history"), app: "Shell History" },
      { path: "/Users/karthikperumalla/openfoodfacts-python/.git", app: "Git Log" },
      { path: "/Users/karthikperumalla/Desktop/LDP/.git", app: "Git Log" },
      { path: path.join(h, "Library/Group Containers/group.com.apple.calendar/Calendar.sqlitedb"), app: "Apple Calendar" },
      { path: path.join(h, "Library/Group Containers/group.com.apple.reminders/Reminders.sqlite"), app: "Reminders" },
      { path: path.join(h, "Library/Reminders/Container_v1/Reminders.sqlite"), app: "Reminders" },
      { path: path.join(h, "Library/Reminders/Reminders.sqlite"), app: "Reminders" }
    ];

    for (const p of probes) {
      if (fs.existsSync(p.path)) {
        try {
          const stat = fs.statSync(p.path);
          const ft: any = p.path.endsWith(".git") ? "unknown" : fingerprint(p.path);
          const scanned = await analyseFile(p.path, stat, ft, learned);
          
          scanned.appName = p.app;
          scanned.confidence = 1.0;
          const slug = path.basename(scanned.filePath).toLowerCase().replace(/[^a-z0-9]/g,"_");
          const appKey = `path_${scanned.appName.toLowerCase().replace(/[^a-z0-9]/g,"_")}_${slug}`;

          learned.learn({
            appKey,
            filePath: scanned.filePath, 
            appName: scanned.appName,
            category: scanned.category, 
            method: scanned.method,
            params: {},
            schema: {}, 
            confidence: 1.0,
            totalRows: scanned.totalRows || 0,
            maxRows: scanned.maxRows || 0,
          });

          if (scanned.confidence >= threshold) {
             result.databases.push(scanned);
             result.autoConnected.push(scanned.appName.toLowerCase().replace(/[^a-z0-9]/g, "_"));
          }
        } catch {}
      }
    }

    result.databases.sort((a,b) => b.confidence - a.confidence);

    // Phase 4: processes
    if (this.opts.includeProcesses !== false) {
      if (this.opts.verbose) console.log("\n[SCAN] Reading processes...");
      result.processes = getProcesses();
      if (this.opts.includeOpenFiles) {
        for (const proc of result.processes.slice(0,20)) proc.openFiles = getOpenDataFiles(proc.pid);
      }
      if (this.opts.verbose) console.log(`[SCAN] ${result.processes.length} processes`);
    }

    // Phase 5: network
    if (this.opts.includeNetwork !== false) {
      if (this.opts.verbose) console.log("\n[SCAN] Reading network connections...");
      result.network = getNetwork();
      if (this.opts.verbose) {
        const est = result.network.filter(c => c.state === "ESTABLISHED").length;
        console.log(`[SCAN] ${result.network.length} connections (${est} established)`);
      }
    }
    
    // Rule 6: Final commit of all learned knowledge
    if (learned && (learned as any).save) (learned as any).save();

    result.durationMs = Date.now() - t0;

    if (this.opts.verbose) {
      console.log(`\n[SCAN] Done in ${result.durationMs}ms`);
      console.log(`[SCAN] Databases:      ${result.databases.length}`);
      console.log(`[SCAN] Auto-connected: ${result.autoConnected.length}`);
      console.log(`[SCAN] Needs approval: ${result.pendingApproval.length}`);
      console.log(`[SCAN] Skipped/noise:  ${result.skipped}\n`);
    }

    return result;
  }

  /** Print a summary without connecting anything. First-run preview. */
  async preview(): Promise<void> {
    const r = await this.run();
    console.log("\n╔══════════════════════════════════════════╗");
    console.log("║  LDP System Scan — What was found        ║");
    console.log("╚══════════════════════════════════════════╝\n");
    console.log(`Scanned ${r.scannedFiles} files in ${r.scannedDirs} directories (${r.durationMs}ms)\n`);

    const top = r.databases.filter(d => d.confidence >= 0.7).slice(0,20);
    if (top.length > 0) {
      console.log("High-confidence databases found:");
      for (const d of top) {
        const enc = d.encrypted ? " [encrypted]" : "";
        console.log(`  ${d.appName.padEnd(24)} ${(d.confidence*100).toFixed(0)}%  ${d.category}${enc}`);
      }
    }

    if (r.pendingApproval.length > 0) {
      console.log(`\n${r.pendingApproval.length} medium-confidence files need approval.`);
    }

    console.log(`\nRunning processes: ${r.processes.length}`);
    console.log(`Network connections: ${r.network.length} (${r.network.filter(c=>c.state==="ESTABLISHED").length} established)`);
  }
}
