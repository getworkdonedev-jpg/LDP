/**
 * LDP Chrome Connector
 * Reads real Chrome SQLite history on macOS / Linux / Windows.
 * SyntheticChromeConnector for testing without a real browser.
 */

import * as fs   from "node:fs";
import * as os   from "node:os";
import * as path from "node:path";
import type { BaseConnector, ConnectorDescriptor, Row, SchemaMap } from "./types.js";
import { findFirst } from "./base.js";

const CHROME_PATHS: Record<string, string[]> = {
  darwin: [
    "~/Library/Application Support/Google/Chrome/Default/History",
    "~/Library/Application Support/Chromium/Default/History",
  ],
  linux: [
    "~/.config/google-chrome/Default/History",
    "~/.config/chromium/Default/History",
  ],
  win32: [
    String.raw`~\AppData\Local\Google\Chrome\User Data\Default\History`,
  ],
};

const CHROME_SCHEMA: SchemaMap = {
  urls: {
    url:             "full URL visited",
    title:           "page title",
    visit_count:     "total times visited",
    last_visit_time: "Windows FILETIME (microseconds since 1601-01-01)",
    typed_count:     "times typed directly in address bar",
  },
  visits: {
    visit_time:     "Windows FILETIME timestamp",
    visit_duration: "microseconds spent on page",
    transition:     "typed / link / redirect / bookmark",
  },
};

function chromeTimeToUnix(t: number): number {
  return t > 0 ? t / 1_000_000 - 11_644_473_600 : 0;
}

export class ChromeConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name:         "chrome",
    app:          "Google Chrome",
    version:      "1.0",
    dataPaths:    CHROME_PATHS[process.platform] ?? CHROME_PATHS.linux,
    permissions:  ["history.read", "searches.read"],
    namedQueries: {
      top_sites:   "Most visited sites",
      recent:      "Last 100 pages visited",
      searches:    "Search queries entered",
      distractions:"Distracting sites (YouTube, Reddit, Twitter)",
    },
    description: "Chrome browsing history — stays on your device.",
  };

  private dbPath: string | null = null;

  async discover(): Promise<boolean> {
    this.dbPath = findFirst(this.descriptor.dataPaths);
    return this.dbPath !== null;
  }

  async schema(): Promise<SchemaMap> {
    return CHROME_SCHEMA;
  }

  async read(query: string, limit = 500): Promise<Row[]> {
    if (!this.dbPath) return [];
    const Database = (await import("better-sqlite3")).default;
    const tmp = path.join(os.tmpdir(), `ldp_chrome_${Date.now()}.db`);
    try {
      fs.copyFileSync(this.dbPath, tmp);
      const db = new Database(tmp, { readonly: true });
      db.function("ctu", (t: number) => chromeTimeToUnix(t));

      const q   = query.toLowerCase();
      let sql: string;
      const base = `SELECT url, title, visit_count,
                    datetime(ctu(last_visit_time), 'unixepoch') as last_visit
                    FROM urls WHERE hidden = 0`;

      if (/search|google|query/.test(q)) {
        sql = `${base} AND (url LIKE '%search%' OR url LIKE '%?q=%') ORDER BY last_visit_time DESC LIMIT ${limit}`;
      } else if (/top|most|popular/.test(q)) {
        sql = `${base} ORDER BY visit_count DESC LIMIT ${limit}`;
      } else if (/waste|distract|youtube|reddit|social/.test(q)) {
        sql = `${base} AND (url LIKE '%youtube%' OR url LIKE '%reddit%' OR url LIKE '%twitter%' OR url LIKE '%netflix%') ORDER BY visit_count DESC LIMIT ${limit}`;
      } else {
        sql = `${base} ORDER BY last_visit_time DESC LIMIT ${limit}`;
      }

      const rows = db.prepare(sql).all() as Row[];
      db.close();
      const now = Date.now() / 1000;
      return rows.map(r => ({
        ...r,
        _recency: Math.max(0, 1 - (now - new Date(r.last_visit as string).getTime() / 1000) / (30 * 86400)),
      }));
    } catch (e) {
      return [];
    } finally {
      try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    }
  }
}

// ── Synthetic Chrome (testing, no browser needed) ─────────────────────────────

const SYNTH_SITES = [
  ["github.com",               "GitHub",            180, "work"    ],
  ["stackoverflow.com",        "Stack Overflow",    140, "work"    ],
  ["youtube.com",              "YouTube",           200, "distract"],
  ["twitter.com",              "Twitter/X",         160, "social"  ],
  ["reddit.com",               "Reddit",            120, "distract"],
  ["news.ycombinator.com",     "Hacker News",        90, "work"    ],
  ["anthropic.com",            "Anthropic",          55, "work"    ],
  ["google.com/search?q=ldp",  "LDP - Google",       40, "search"  ],
  ["netflix.com",              "Netflix",            85, "distract"],
  ["localhost:3000",           "Local Dev",         110, "work"    ],
] as const;

export class SyntheticChromeConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name: "chrome", app: "Google Chrome", version: "1.0",
    dataPaths: ["synthetic"], permissions: ["history.read"],
    namedQueries: {}, description: "Synthetic Chrome — for testing.",
  };

  private readonly rows: Row[];

  constructor() {
    const now  = Date.now() / 1000;
    this.rows  = SYNTH_SITES.map(([url, title, visits, cat]) => ({
      url:         `https://${url}`,
      title,
      visit_count: visits + Math.floor(Math.random() * 40 - 20),
      last_visit:  new Date((now - Math.random() * 7 * 86400) * 1000)
                     .toISOString().slice(0, 19).replace("T", " "),
      _recency:    Math.random() * 0.7 + 0.3,
      _category:   cat,
    }));
  }

  async discover(): Promise<boolean> { return true; }
  async schema():   Promise<SchemaMap> { return CHROME_SCHEMA; }

  async read(query: string, limit = 500): Promise<Row[]> {
    const q = query.toLowerCase();
    let rows = [...this.rows];
    if (/search|query/.test(q))
      rows = rows.filter(r => r._category === "search");
    else if (/waste|distract|social/.test(q))
      rows = rows.filter(r => ["distract", "social"].includes(r._category as string));
    else if (/top|most/.test(q))
      rows.sort((a, b) => (b.visit_count as number) - (a.visit_count as number));
    else
      rows.sort((a, b) => String(b.last_visit) > String(a.last_visit) ? 1 : -1);
    return rows.slice(0, limit);
  }
}
