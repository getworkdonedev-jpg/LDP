/**
 * LDP Engine — core runtime.
 * Manages connectors, enforces consent, encrypts all state,
 * packs context, handles write intents, logs everything.
 *
 * FIXES APPLIED:
 *   CRITICAL-02 — AuditLog race condition: queue now cleared only AFTER
 *                 confirmed successful write, not before.
 *   HIGH-05     — Consent bypass: fingerprint re-verified on every connect(),
 *                 not just at grant time.
 *   HIGH-06     — ContextPacker empty query: filter out empty tokens so
 *                 "" does not match every chunk.
 *   MEDIUM-08   — engine.query() source errors now returned in payload
 *                 as sourceErrors{} instead of being silently swallowed.
 */

import * as fs   from "node:fs";
import * as path from "node:path";
import {
  MsgType, RiskTier, LDPMessage, ConnectorDescriptor,
  BaseConnector, Row, ContextResult,
  ConsentRecord, ConsentRequest, EngineReport,
  ApprovalCallback,
  createMessage, ackMessage, errorMessage, isAck,
} from "./types.js";
import { LDPCrypto, getCrypto, LDP_DIR } from "./crypto.js";

// ── Schema Cache ──────────────────────────────────────────────────────────────

export class SchemaCache {
  private readonly file:   string;
  private readonly crypto: LDPCrypto;
  private mem: Record<string, unknown>;

  constructor(file: string) {
    this.file   = file;
    this.crypto = getCrypto();
    this.mem    = this.crypto.readEncrypted(file);
  }

  get(app: string, fp: string): unknown          { return this.mem[`${app}:${fp}`]; }
  set(app: string, fp: string, schema: unknown): void {
    this.mem[`${app}:${fp}`] = schema;
    this.crypto.writeEncrypted(this.file, this.mem);
  }
}

// ── Consent Store ─────────────────────────────────────────────────────────────

export class ConsentStore {
  private readonly file:   string;
  private readonly crypto: LDPCrypto;
  private store: Record<string, ConsentRecord>;

  constructor(file: string) {
    this.file   = file;
    this.crypto = getCrypto();
    this.store  = this.crypto.readEncrypted(file);
  }

  /**
   * FIX HIGH-05: re-verify fingerprint on every call.
   * Original only checked that a record existed for the name.
   * An attacker could swap a connector's descriptor after consent was
   * granted and the old record would still pass.
   */
  hasConsent(descriptor: ConnectorDescriptor): boolean {
    const rec = this.store[descriptor.name];
    return !!rec && rec.fingerprint === getCrypto().hashDescriptor(descriptor);
  }

  grant(descriptor: ConnectorDescriptor, grantedBy = "user"): void {
    this.store[descriptor.name] = {
      fingerprint: getCrypto().hashDescriptor(descriptor),
      grantedAt:   Date.now() / 1000,
      grantedBy,
      app:         descriptor.app,
      permissions: [...descriptor.permissions],
    };
    this.crypto.writeEncrypted(this.file, this.store);
  }

  revoke(name: string): void {
    delete this.store[name];
    this.crypto.writeEncrypted(this.file, this.store);
  }

  listConsented(): string[] { return Object.keys(this.store); }
}

// ── Context Packer ────────────────────────────────────────────────────────────

export class ContextPacker {
  private readonly budget: number;
  private readonly k1 = 1.2;
  private readonly b  = 0.75;

  constructor(tokenBudget = 8_000) { this.budget = tokenBudget; }

  /**
   * BM25 relevance scoring.
   * score(D, Q) = Σ [ IDF(q_i) * (f(q_i, D) * (k1 + 1)) / (f(q_i, D) + k1 * (1 - b + b * (|D| / avgdl))) ]
   */
  pack(sources: Record<string, Row[]>, query: string): ContextResult {
    const allRows: Row[] = [];
    for (const [src, rows] of Object.entries(sources)) {
      for (const row of rows) {
        allRows.push({ ...row, _src: src });
      }
    }

    const qWords = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (qWords.length === 0 || allRows.length === 0) {
      return this.packBasic(allRows, query, sources);
    }

    // Pass 1: Global Stats
    const N = allRows.length;
    const docTexts = allRows.map(r => Object.values(r).join(" ").toLowerCase());
    const docLens  = docTexts.map(t => t.split(/\s+/).length);
    const avgdl    = docLens.reduce((a, b) => a + b, 0) / N;

    const idfs: Record<string, number> = {};
    for (const word of qWords) {
      const n = docTexts.filter(t => t.includes(word)).length;
      idfs[word] = Math.log(1 + (N - n + 0.5) / (n + 0.5));
    }

    // Pass 2: BM25 Scoring
    const scored: Array<[number, Row]> = allRows.map((row, i) => {
      const text = docTexts[i];
      const Ld   = docLens[i];
      
      let bm25 = 0;
      for (const word of qWords) {
        const tf = (text.split(word).length - 1); // simple frequency
        const idf = idfs[word] ?? 0;
        bm25 += idf * (tf * (this.k1 + 1)) / (tf + this.k1 * (1 - this.b + this.b * (Ld / avgdl)));
      }

      const recency = (row._recency as number) ?? 0.5;
      const weight  = (row._weight  as number) ?? 1.0;

      // Final score: BM25 (scaled) + recency + weight
      // Normalized BM25 to 0-1 range roughly for combination
      const finalScore = (Math.tanh(bm25) * 0.6) + (recency * 0.3) + (weight * 0.1);
      return [finalScore, row];
    });

    return this.assemble(scored, query, sources);
  }

  private packBasic(allRows: Row[], query: string, sources: Record<string, Row[]>): ContextResult {
    const scored: Array<[number, Row]> = allRows.map(row => {
      const recency = (row._recency as number) ?? 0.5;
      const weight  = (row._weight  as number) ?? 1.0;
      return [(recency * 0.8) + (weight * 0.2), row];
    });
    return this.assemble(scored, query, sources);
  }

  private assemble(scored: Array<[number, Row]>, query: string, sources: Record<string, Row[]>): ContextResult {
    scored.sort(([a], [b]) => b - a);

    const packed: Row[] = [];
    let tokens = 0;
    for (const [, row] of scored) {
      const t = Math.floor(JSON.stringify(row).length / 4);
      if (tokens + t > this.budget) break;
      packed.push(row);
      tokens += t;
    }

    const totalRows = Object.values(sources).reduce((s, r) => s + r.length, 0);
    return {
      query, chunks: packed, tokensUsed: tokens,
      sources: Object.keys(sources), totalRows, packedRows: packed.length,
    };
  }
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

export class AuditLog {
  private readonly file:   string;
  private readonly crypto: LDPCrypto;
  private queue:  unknown[] = [];
  private timer:  ReturnType<typeof setInterval> | null = null;

  constructor(file: string) {
    this.file   = file;
    this.crypto = getCrypto();
  }

  start(): void {
    this.timer = setInterval(() => this.flush(), 500);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.flush();
  }

  /**
   * FIX CRITICAL-02: original cleared the queue BEFORE writing.
   * If writeEncrypted threw, the queued entries were permanently lost.
   *
   * Fix: capture the batch, attempt the write, and only splice those
   * entries out of the queue AFTER the write succeeds.
   * On failure the entries remain in the queue and are retried on the
   * next flush() call.
   */
  private flush(): void {
    if (!this.queue.length) return;

    // Snapshot current queue — do NOT clear it yet
    const batch = [...this.queue];

    try {
      const existing = this.crypto.readEncrypted<{ entries: unknown[] }>(this.file);
      const all      = [...(existing.entries ?? []), ...batch].slice(-10_000);
      this.crypto.writeEncrypted(this.file, { entries: all });

      // Only remove entries that were successfully written
      this.queue.splice(0, batch.length);
    } catch {
      // Non-fatal: entries stay in queue, retried next tick
    }
  }

  log(
    event: string,
    connector: string,
    details: Record<string, unknown> = {},
    risk: RiskTier = RiskTier.READ,
  ): void {
    this.queue.push({ ts: Date.now() / 1000, event, connector, risk, ...details });
  }

  readLog(): unknown[] {
    try {
      return this.crypto.readEncrypted<{ entries: unknown[] }>(this.file).entries ?? [];
    } catch { return []; }
  }
}

// ── LDP Engine ────────────────────────────────────────────────────────────────

export interface LDPEngineOptions {
  dataDir?:     string;
  tokenBudget?: number;
  approvalCb?:  ApprovalCallback;
}

export class LDPEngine {
  private readonly dataDir:  string;
  private readonly cache:    SchemaCache;
  private readonly consent:  ConsentStore;
  private readonly packer:   ContextPacker;
  readonly audit:            AuditLog;

  // FIX HIGH-04: connectors is now public readonly so MCPAdapter
  // can access it without the unsafe (this.engine as any) cast.
  readonly connectors = new Map<string, BaseConnector>();
  private connected   = new Set<string>();
  private approvalCb: ApprovalCallback | null;

  readonly stats = {
    messages: 0, discovers: 0, reads: 0,
    cacheHits: 0, cacheMisses: 0,
    consentGranted: 0, consentDenied: 0,
    writeIntents: 0, approved: 0, rejected: 0,
    errors: 0,
  };

  constructor(opts: LDPEngineOptions = {}) {
    this.dataDir   = opts.dataDir ?? LDP_DIR;
    this.approvalCb = opts.approvalCb ?? null;
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    this.cache   = new SchemaCache (path.join(this.dataDir, "schema_cache.enc"));
    this.consent = new ConsentStore(path.join(this.dataDir, "consent.enc"));
    this.audit   = new AuditLog   (path.join(this.dataDir, "audit.enc"));
    this.packer  = new ContextPacker(opts.tokenBudget);
  }

  start(): this { this.audit.start(); return this; }
  stop():  void { this.audit.stop(); }

  setApprovalCallback(cb: ApprovalCallback): this {
    this.approvalCb = cb;
    return this;
  }

  register(connector: BaseConnector): this {
    this.connectors.set(connector.descriptor.name, connector);
    return this;
  }

  // ── Consent ───────────────────────────────────────────────────────────────

  requestConsent(name: string): ConsentRequest | { error: string } {
    const c = this.connectors.get(name);
    if (!c) return { error: `Unknown connector: ${name}` };
    const d = c.descriptor;
    return {
      connector:   name,
      app:         d.app,
      permissions: d.permissions,
      dataPaths:   d.dataPaths,
      description: d.description,
      fingerprint: getCrypto().hashDescriptor(d),
      prompt: `LDP wants to read your ${d.app} data.\nPermissions: ${d.permissions.join(", ")}\nData stays on your device.\nApprove?`,
    };
  }

  grantConsent(name: string, grantedBy = "user"): boolean {
    const c = this.connectors.get(name);
    if (!c) return false;
    this.consent.grant(c.descriptor, grantedBy);
    this.stats.consentGranted++;
    this.audit.log("CONSENT_GRANTED", name, { grantedBy });
    return true;
  }

  revokeConsent(name: string): void {
    this.connected.delete(name);
    this.consent.revoke(name);
    this.audit.log("CONSENT_REVOKED", name);
  }

  // ── Connect ───────────────────────────────────────────────────────────────

  async connect(name: string, autoConsent = false): Promise<LDPMessage> {
    const c = this.connectors.get(name);
    if (!c) return errorMessage(`Unknown connector: ${name}`);

    /**
     * FIX HIGH-05: hasConsent() now re-verifies the live descriptor
     * fingerprint on every call (moved fix into ConsentStore.hasConsent).
     * If the descriptor changed since consent was granted, this returns
     * false and the user must re-approve.
     */
    if (!this.consent.hasConsent(c.descriptor)) {
      if (autoConsent) {
        this.grantConsent(name, "auto");
      } else {
        this.stats.consentDenied++;
        return createMessage(MsgType.ERROR, {
          error:          "consent_required",
          consentRequest: this.requestConsent(name),
        });
      }
    }

    this.stats.discovers++;
    let found: boolean;
    try   { found = await c.discover(); }
    catch (e) {
      this.stats.errors++;
      return errorMessage(`discover failed: ${String(e)}`);
    }

    if (!found) {
      this.stats.errors++;
      return errorMessage(`${name}: app data not found on this machine`);
    }

    const fp     = getCrypto().hashDescriptor(c.descriptor);
    const cached = this.cache.get(c.descriptor.app, fp);
    if (cached) {
      this.stats.cacheHits++;
    } else {
      this.cache.set(c.descriptor.app, fp, await c.schema());
      this.stats.cacheMisses++;
    }

    this.connected.add(name);
    this.stats.messages++;
    this.audit.log("CONNECT", name, { fingerprint: fp });
    return ackMessage({ connector: name, status: "connected",
                        cache: cached ? "hit" : "mapped" });
  }

  // ── Query ─────────────────────────────────────────────────────────────────

  async query(question: string, sources?: string[]): Promise<LDPMessage> {
    const targets = sources ?? [...this.connected];
    if (!targets.length) return errorMessage("No connected sources");

    const raw: Record<string, Row[]> = {};

    /**
     * FIX MEDIUM-08: source errors are no longer silently swallowed.
     * Each connector failure is captured in sourceErrors{} and returned
     * inside the CONTEXT payload so callers can see which sources failed.
     */
    const sourceErrors: Record<string, string> = {};

    for (const name of targets) {
      if (!this.connected.has(name)) continue;
      try {
        const rows = await this.connectors.get(name)!.read(question);
        raw[name]  = rows;
        this.stats.reads++;
        this.audit.log("READ", name, { query: question.slice(0, 80), rows: rows.length });
      } catch (e) {
        this.stats.errors++;
        sourceErrors[name] = String(e);
        this.audit.log("READ_ERROR", name, { query: question.slice(0, 80), error: String(e) });
      }
    }

    const ctx = this.packer.pack(raw, question);
    this.stats.messages++;

    return createMessage(MsgType.CONTEXT, {
      ...(ctx as unknown as Record<string, unknown>),
      sourceErrors,   // callers can inspect which sources errored
    });
  }

  // ── Write Intent ──────────────────────────────────────────────────────────

  async writeIntent(
    action:    string,
    payload:   Record<string, unknown>,
    risk:      RiskTier,
    connector  = "unknown",
  ): Promise<LDPMessage> {
    const msg = createMessage(
      MsgType.WRITE_INTENT,
      { action, ...payload },
      { risk, source: connector },
    );
    this.stats.writeIntents++;
    this.audit.log("WRITE_INTENT", connector, { action, risk });

    let approved: boolean;
    if (risk === RiskTier.READ || risk === RiskTier.LOW) {
      approved = true;
    } else if (this.approvalCb) {
      approved = await this.approvalCb(msg);
    } else {
      console.warn(`[LDP] [WRITE_INTENT ${risk}] '${action}' — set approvalCallback for production`);
      approved = true;
    }

    if (approved) {
      this.stats.approved++;
      this.audit.log("WRITE_APPROVED", connector, { action });
      return ackMessage({ action, approved: true });
    }
    this.stats.rejected++;
    this.audit.log("WRITE_REJECTED", connector, { action });
    return errorMessage(`Write rejected: ${action}`);
  }

  // ── Disconnect ────────────────────────────────────────────────────────────

  disconnect(name: string): void {
    this.connected.delete(name);
    this.audit.log("DISCONNECT", name);
  }

  // ── Report ────────────────────────────────────────────────────────────────

  report(): EngineReport {
    return {
      ...this.stats,
      connected:  [...this.connected],
      registered: [...this.connectors.keys()],
      consented:  this.consent.listConsented(),
    };
  }
}
