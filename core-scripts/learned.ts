/**
 * LDP Learned Knowledge Base — Superposition Identity
 * ====================================================
 * Replaces the 15-target hardcoded app list with a self-improving
 * knowledge base that grows with every new machine it runs on.
 *
 * Core concept — SUPERPOSITION:
 *   Unknown file → { "Signal": 0.82, "Telegram": 0.11, "Unknown": 0.07 }
 *   All identities held simultaneously until first successful query.
 *   Winning identity written to learned_apps.json permanently.
 *   Next run: instant load, no scan, no AI call.
 *
 * ~/.ldp/learned_apps.json  — encrypted with AES-256-GCM (machine-bound key)
 *
 * Usage:
 *   import { LearnedBase } from "@ldp-protocol/sdk";
 *
 *   const base = new LearnedBase();
 *   await base.load();
 *
 *   // Check if path is already known
 *   const known = base.lookup("/path/to/db.sqlite");
 *   if (known) {
 *     console.log(known.appName, known.method); // instant
 *   }
 *
 *   // Add newly identified app
 *   base.learn({
 *     filePath: "/path/to/db.sqlite",
 *     appName:  "Signal",
 *     category: "messaging",
 *     method:   "sqlcipher_pbkdf2_spaces_iv",
 *     schema:   { messages: ["body", "sent_at"], conversations: ["name"] },
 *     confidence: 0.97,
 *   });
 *
 *   // Superposition: hold multiple candidates until collapsed
 *   const candidates = base.superpose([
 *     { appName: "Signal",   confidence: 0.82, schema: {...} },
 *     { appName: "Telegram", confidence: 0.11, schema: {...} },
 *   ]);
 *   // First connector that returns rows collapses the superposition
 *   base.collapse(candidates.id, "Signal");
 */

import * as fs   from "node:fs";
import * as path from "node:path";
import * as os   from "node:os";
import * as crypto from "node:crypto";
import { getCrypto, LDP_DIR } from "./crypto.js";
import type { DecryptMethod, DataCategory } from "./brain.js";

// ── File path ────────────────────────────────────────────────────────────────
const LEARNED_FILE = path.join(LDP_DIR, "learned_apps.json");

// ── Types ────────────────────────────────────────────────────────────────────

export interface LearnedApp {
  /** Unique key — derived from path fingerprint */
  appKey:         string;
  /** Display name */
  appName:        string;
  /** Exact path on THIS machine */
  filePath:       string;
  /** Data category */
  category:       DataCategory;
  /** How to open the database */
  method:         DecryptMethod;
  /** AES key or other method params (stored encrypted) */
  params:         Record<string, unknown>;
  /** Table → column names snapshot */
  schema:         Record<string, string[]>;
  /** 0–1 confidence in the identification */
  confidence:     number;
  /** Unix timestamp of first identification */
  firstSeen:      number;
  /** Last time this app was successfully connected */
  lastConnected:  number;
  /** Total successful connections */
  timesConnected: number;
  /** OS when first identified */
  firstSeenOS:    string;
  /** Superposition state — null = collapsed to single identity */
  superpositionId?: string | null;
}

/** A candidate identity held in superposition */
export interface SuperpositionCandidate {
  appName:    string;
  confidence: number;
  schema:     Record<string, string[]>;
  method:     DecryptMethod;
  params?:    Record<string, unknown>;
}

/** A superposition group — multiple candidate identities for one file */
export interface SuperpositionGroup {
  id:           string;
  filePath:     string;
  candidates:   SuperpositionCandidate[];
  createdAt:    number;
  /** Set when first query collapses to winner */
  collapsedTo?: string;
}

// ── Key derivation ────────────────────────────────────────────────────────────

function makeAppKey(filePath: string): string {
  /** Stable key: last two path segments + filename, hashed.
   *  Survives home directory changes between machines. */
  const segs = filePath.split(path.sep).filter(Boolean);
  const stable = segs.slice(-3).join("/");
  return crypto.createHash("sha256").update(stable).digest("hex").slice(0, 16);
}

// ── LearnedBase ───────────────────────────────────────────────────────────────

export class LearnedBase {
  private apps   = new Map<string, LearnedApp>();
  private groups = new Map<string, SuperpositionGroup>();
  private readonly cry = getCrypto();
  private dirty = false;

  constructor() { this.load(); }

  // ── Persistence ─────────────────────────────────────────────────────────────

  private load(): void {
    try {
      const raw = this.cry.readEncrypted<{
        apps:   Record<string, LearnedApp>;
        groups: Record<string, SuperpositionGroup>;
      }>(LEARNED_FILE);
      for (const [k, v] of Object.entries(raw.apps   ?? {})) this.apps.set(k, v);
      for (const [k, v] of Object.entries(raw.groups ?? {})) this.groups.set(k, v);
    } catch {}
  }

  private flush(): void {
    if (!this.dirty) return;
    const obj = {
      apps:   Object.fromEntries(this.apps),
      groups: Object.fromEntries(this.groups),
    };
    this.cry.writeEncrypted(LEARNED_FILE, obj);
    this.dirty = false;
  }

  /** Call after batch operations to persist. */
  save(): void {
    this.dirty = true;
    this.flush();
  }

  // ── Core operations ─────────────────────────────────────────────────────────

  /**
   * Store a newly identified app.
   * If it already exists, updates lastConnected + timesConnected.
   */
  learn(info: {
    filePath:   string;
    appName:    string;
    category:   DataCategory;
    method:     DecryptMethod;
    params?:    Record<string, unknown>;
    schema?:    Record<string, string[]>;
    confidence: number;
  }): LearnedApp {
    const appKey  = makeAppKey(info.filePath);
    const existing = this.apps.get(appKey);
    const now = Date.now() / 1000;

    const entry: LearnedApp = {
      appKey,
      appName:        info.appName,
      filePath:       info.filePath,
      category:       info.category,
      method:         info.method,
      params:         info.params ?? {},
      schema:         info.schema ?? {},
      confidence:     info.confidence,
      firstSeen:      existing?.firstSeen ?? now,
      lastConnected:  now,
      timesConnected: (existing?.timesConnected ?? 0) + 1,
      firstSeenOS:    existing?.firstSeenOS ?? `${os.platform()} ${os.release()}`,
      superpositionId: null,
    };

    this.apps.set(appKey, entry);
    this.save();
    console.log(`[LEARNED] Saved: ${info.appName} (${(info.confidence*100).toFixed(0)}% confidence)`);
    return entry;
  }

  /**
   * Look up a file path. Returns null if not yet learned.
   * Tries exact match first, then path-fingerprint match.
   */
  lookup(filePath: string): LearnedApp | null {
    const key = makeAppKey(filePath);
    if (this.apps.has(key)) return this.apps.get(key)!;

    // Fallback: exact path match (for files moved between machines)
    for (const app of this.apps.values()) {
      if (app.filePath === filePath) return app;
    }
    return null;
  }

  /** Look up by app name (partial match, case-insensitive). */
  lookupByName(appName: string): LearnedApp | null {
    const n = appName.toLowerCase();
    for (const app of this.apps.values()) {
      if (app.appName.toLowerCase().includes(n)) return app;
    }
    return null;
  }

  /** All apps not yet learned (paths in `candidates` not in knowledge base). */
  unknownPaths(candidates: string[]): string[] {
    return candidates.filter(p => this.lookup(p) === null);
  }

  /** All learned apps. */
  list(): LearnedApp[] {
    return [...this.apps.values()].sort((a,b) => b.lastConnected - a.lastConnected);
  }

  size():  number { return this.apps.size; }
  clear()         { this.apps.clear(); this.groups.clear(); this.save(); }

  // ── Superposition ─────────────────────────────────────────────────────────

  /**
   * Register a set of candidate identities for an unknown file.
   * Returns a SuperpositionGroup with a unique ID.
   * Call collapse() when the first query succeeds.
   */
  superpose(filePath: string, candidates: SuperpositionCandidate[]): SuperpositionGroup {
    const id = crypto.randomBytes(6).toString("hex");
    const sorted = [...candidates].sort((a,b) => b.confidence - a.confidence);
    const group: SuperpositionGroup = {
      id,
      filePath,
      candidates: sorted,
      createdAt:  Date.now() / 1000,
    };
    this.groups.set(id, group);
    this.save();
    console.log(
      `[LEARNED] Superposition(${id}): ${sorted.map(c => `${c.appName}(${(c.confidence*100).toFixed(0)}%)`).join(" | ")}`
    );
    return group;
  }

  /**
   * A query succeeded — collapse the superposition to the winning identity.
   * Stores the winner in the main knowledge base and removes the group.
   */
  collapse(groupId: string, winnerName: string): LearnedApp | null {
    const group = this.groups.get(groupId);
    if (!group) return null;

    const winner = group.candidates.find(c => c.appName === winnerName)
      ?? group.candidates[0];

    if (!winner) return null;

    group.collapsedTo = winnerName;
    this.groups.delete(groupId);

    const app = this.learn({
      filePath:   group.filePath,
      appName:    winner.appName,
      category:   "other",   // caller should pass real category
      method:     winner.method,
      params:     winner.params ?? {},
      schema:     winner.schema,
      confidence: Math.min(winner.confidence + 0.10, 1.0),  // boost on proven success
    });

    console.log(`[LEARNED] Collapsed: ${winnerName} won — confidence boosted to ${(app.confidence*100).toFixed(0)}%`);
    return app;
  }

  /** All open (not yet collapsed) superposition groups. */
  openGroups(): SuperpositionGroup[] {
    return [...this.groups.values()].filter(g => !g.collapsedTo);
  }

  /** Get the highest-confidence candidate for a file path (before collapse). */
  bestCandidate(filePath: string): SuperpositionCandidate | null {
    for (const g of this.groups.values()) {
      if (g.filePath === filePath && !g.collapsedTo) {
        return g.candidates[0] ?? null;
      }
    }
    return null;
  }

  // ── Delta sync support ───────────────────────────────────────────────────────

  private syncState: Record<string, number> = {};

  getLastReadAt(connectorName: string): number {
    try {
      const raw = this.cry.readEncrypted<Record<string, number>>(
        path.join(LDP_DIR, "sync_state.json")
      );
      return raw[connectorName] ?? 0;
    } catch { return 0; }
  }

  markReadAt(connectorName: string, ts = Date.now() / 1000): void {
    try {
      const file = path.join(LDP_DIR, "sync_state.json");
      const raw = this.cry.readEncrypted<Record<string, number>>(file);
      raw[connectorName] = ts;
      this.cry.writeEncrypted(file, raw);
    } catch {}
  }

  // ── Summary ───────────────────────────────────────────────────────────────

  summary(): {
    total:       number;
    byCategory:  Record<string, number>;
    openGroups:  number;
    encrypted:   number;
  } {
    const byCategory: Record<string, number> = {};
    let encrypted = 0;
    for (const app of this.apps.values()) {
      byCategory[app.category] = (byCategory[app.category] ?? 0) + 1;
      if (app.method !== "plain_sqlite") encrypted++;
    }
    return {
      total:      this.apps.size,
      byCategory,
      openGroups: this.openGroups().length,
      encrypted,
    };
  }
}

// ── Singleton ─────────────────────────────────────────────────────────────────
let _instance: LearnedBase | null = null;
export function getLearnedBase(): LearnedBase {
  return (_instance ??= new LearnedBase());
}
