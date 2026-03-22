/**
 * LDP Chrome Connector
 * Reads real Chrome SQLite history on macOS / Linux / Windows.
 * SyntheticChromeConnector for testing without a real browser.
 *
 * FIX CRITICAL-01: chromeTimeToUnix now validates input bounds.
 * Chrome stores timestamps as microseconds since 1601-01-01.
 * The original had no guard: values near Number.MAX_SAFE_INTEGER
 * produced Infinity or NaN after division, breaking date formatting.
 *
 * Fix: clamp t to a sane range before conversion.
 * Valid Chrome timestamps are between ~1970 and ~2100 in Unix time.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { findFirst } from "./base.js";
const CHROME_PATHS = {
    darwin: [
        "~/Library/Application Support/Google/Chrome/Default/History",
        "~/Library/Application Support/Chromium/Default/History",
    ],
    linux: [
        "~/.config/google-chrome/Default/History",
        "~/.config/chromium/Default/History",
    ],
    win32: [
        String.raw `~\AppData\Local\Google\Chrome\User Data\Default\History`,
    ],
};
const CHROME_SCHEMA = {
    urls: {
        url: "full URL visited",
        title: "page title",
        visit_count: "total times visited",
        last_visit_time: "Windows FILETIME (microseconds since 1601-01-01)",
        typed_count: "times typed directly in address bar",
    },
    visits: {
        visit_time: "Windows FILETIME timestamp",
        visit_duration: "microseconds spent on page",
        transition: "typed / link / redirect / bookmark",
    },
};
// ── FIX CRITICAL-01 ───────────────────────────────────────────────────────────
// Chrome epoch offset: seconds between 1601-01-01 and 1970-01-01
const CHROME_EPOCH_OFFSET = 11_644_473_600;
// Smallest valid Chrome timestamp  (~1970-01-01 in Chrome epoch, microseconds)
const CHROME_TS_MIN = CHROME_EPOCH_OFFSET * 1_000_000;
// Largest valid Chrome timestamp   (~2100-01-01 in Chrome epoch, microseconds)
const CHROME_TS_MAX = (CHROME_EPOCH_OFFSET + 4_102_444_800) * 1_000_000;
function chromeTimeToUnix(t) {
    if (!Number.isFinite(t) || t <= 0)
        return 0;
    if (t < CHROME_TS_MIN || t > CHROME_TS_MAX)
        return 0; // out of sane range
    return t / 1_000_000 - CHROME_EPOCH_OFFSET;
}
// ─────────────────────────────────────────────────────────────────────────────
export class ChromeConnector {
    descriptor = {
        name: "chrome",
        app: "Google Chrome",
        version: "1.0",
        dataPaths: CHROME_PATHS[process.platform] ?? CHROME_PATHS.linux,
        permissions: ["history.read", "searches.read"],
        namedQueries: {
            top_sites: "Most visited sites",
            recent: "Last 100 pages visited",
            searches: "Search queries entered",
            distractions: "Instagram, YouTube, Reddit, TikTok",
        },
        description: "Chrome browsing history — stays on your device.",
    };
    dbPath = null;
    async discover() {
        this.dbPath = findFirst(this.descriptor.dataPaths);
        return this.dbPath !== null;
    }
    async schema() { return CHROME_SCHEMA; }
    async read(query, limit = 500) {
        if (!this.dbPath)
            return [];
        const Database = (await import("better-sqlite3")).default;
        const tmp = path.join(os.tmpdir(), `ldp_chrome_${Date.now()}.db`);
        try {
            fs.copyFileSync(this.dbPath, tmp);
            const db = new Database(tmp, { readonly: true });
            // Register the fixed converter as a SQLite scalar function
            db.function("ctu", (t) => chromeTimeToUnix(t));
            const q = query.toLowerCase();
            let sql;
            const base = `SELECT url, title, visit_count,
                    datetime(ctu(last_visit_time), 'unixepoch') as last_visit
                    FROM urls WHERE hidden = 0`;
            if (/search|google|query/.test(q)) {
                sql = `${base} AND (url LIKE '%search%' OR url LIKE '%?q=%') ORDER BY last_visit_time DESC LIMIT ${limit}`;
            }
            else if (/top|most|popular/.test(q)) {
                sql = `${base} ORDER BY visit_count DESC LIMIT ${limit}`;
            }
            else if (/waste|distract|youtube|reddit|social/.test(q)) {
                sql = `${base} AND (url LIKE '%youtube%' OR url LIKE '%reddit%' OR url LIKE '%twitter%' OR url LIKE '%instagram%' OR url LIKE '%tiktok%' OR url LIKE '%netflix%') ORDER BY visit_count DESC LIMIT ${limit}`;
            }
            else {
                sql = `${base} ORDER BY last_visit_time DESC LIMIT ${limit}`;
            }
            const rows = db.prepare(sql).all();
            db.close();
            const now = Date.now() / 1000;
            return rows.map(r => ({
                ...r,
                _recency: Math.max(0, 1 - (now - new Date(r.last_visit).getTime() / 1000) / (30 * 86400)),
            }));
        }
        catch {
            return [];
        }
        finally {
            try {
                fs.unlinkSync(tmp);
            }
            catch { /* ignore */ }
        }
    }
}
// ── Synthetic Chrome (testing, no browser needed) ─────────────────────────────
const SYNTH_SITES = [
    ["github.com", "GitHub", 180, "work"],
    ["stackoverflow.com", "Stack Overflow", 140, "work"],
    ["youtube.com", "YouTube", 200, "distract"],
    ["twitter.com", "Twitter/X", 160, "social"],
    ["reddit.com", "Reddit", 120, "distract"],
    ["news.ycombinator.com", "Hacker News", 90, "work"],
    ["anthropic.com", "Anthropic", 55, "work"],
    ["google.com/search?q=ldp", "LDP - Google", 40, "search"],
    ["netflix.com", "Netflix", 85, "distract"],
    ["instagram.com", "Instagram", 95, "social"],
    ["tiktok.com", "TikTok", 70, "distract"],
    ["localhost:3000", "Local Dev", 110, "work"],
];
export class SyntheticChromeConnector {
    descriptor = {
        name: "chrome", app: "Google Chrome", version: "1.0",
        dataPaths: ["synthetic"], permissions: ["history.read"],
        namedQueries: {}, description: "Synthetic Chrome — for testing.",
    };
    rows;
    constructor() {
        /**
         * FIX MEDIUM-09: use a seeded deterministic LCG (linear congruential
         * generator) instead of Math.random(). Synthetic connectors now produce
         * stable, reproducible data across runs, making tests reliable.
         */
        const rng = makeLCG(42);
        const now = Date.now() / 1000;
        this.rows = SYNTH_SITES.map(([url, title, visits, cat]) => ({
            url: `https://${url}`,
            title,
            visit_count: visits + Math.floor(rng() * 40 - 20),
            last_visit: new Date((now - rng() * 7 * 86400) * 1000)
                .toISOString().slice(0, 19).replace("T", " "),
            _recency: rng() * 0.7 + 0.3,
            _category: cat,
        }));
    }
    async discover() { return true; }
    async schema() { return CHROME_SCHEMA; }
    async read(query, limit = 500) {
        const q = query.toLowerCase();
        let rows = [...this.rows];
        if (/search|query/.test(q))
            rows = rows.filter(r => r._category === "search");
        else if (/waste|distract|social/.test(q))
            rows = rows.filter(r => ["distract", "social"].includes(r._category));
        else if (/top|most/.test(q))
            rows.sort((a, b) => b.visit_count - a.visit_count);
        else
            rows.sort((a, b) => String(b.last_visit) > String(a.last_visit) ? 1 : -1);
        return rows.slice(0, limit);
    }
}
/**
 * FIX MEDIUM-09: seeded deterministic LCG.
 * Returns a function that produces the same sequence on every run.
 * Constants from Numerical Recipes (Knuth).
 */
function makeLCG(seed) {
    let s = seed >>> 0;
    return () => {
        s = (Math.imul(1664525, s) + 1013904223) >>> 0;
        return s / 0x100000000;
    };
}
//# sourceMappingURL=chrome.js.map