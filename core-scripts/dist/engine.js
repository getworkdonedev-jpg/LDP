/**
 * LDP Engine — core runtime.
 * Manages connectors, enforces consent, encrypts all state,
 * packs context, handles write intents, logs everything.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { MsgType, RiskTier, createMessage, ackMessage, errorMessage, } from "./types.js";
import { getCrypto, LDP_DIR } from "./crypto.js";
// ── Schema Cache ──────────────────────────────────────────────────────────────
export class SchemaCache {
    file;
    crypto;
    mem;
    constructor(file) {
        this.file = file;
        this.crypto = getCrypto();
        this.mem = this.crypto.readEncrypted(file);
    }
    get(app, fp) {
        return this.mem[`${app}:${fp}`];
    }
    set(app, fp, schema) {
        this.mem[`${app}:${fp}`] = schema;
        this.crypto.writeEncrypted(this.file, this.mem);
    }
}
// ── Consent Store ─────────────────────────────────────────────────────────────
export class ConsentStore {
    file;
    crypto;
    store;
    constructor(file) {
        this.file = file;
        this.crypto = getCrypto();
        this.store = this.crypto.readEncrypted(file);
    }
    hasConsent(descriptor) {
        const rec = this.store[descriptor.name];
        return !!rec && rec.fingerprint === getCrypto().hashDescriptor(descriptor);
    }
    grant(descriptor, grantedBy = "user") {
        this.store[descriptor.name] = {
            fingerprint: getCrypto().hashDescriptor(descriptor),
            grantedAt: Date.now() / 1000,
            grantedBy,
            app: descriptor.app,
            permissions: [...descriptor.permissions],
        };
        this.crypto.writeEncrypted(this.file, this.store);
    }
    revoke(name) {
        delete this.store[name];
        this.crypto.writeEncrypted(this.file, this.store);
    }
    listConsented() {
        return Object.keys(this.store);
    }
}
// ── Context Packer ────────────────────────────────────────────────────────────
export class ContextPacker {
    budget;
    constructor(tokenBudget = 8_000) {
        this.budget = tokenBudget;
    }
    score(row, query) {
        const qWords = new Set(query.toLowerCase().split(/\s+/));
        const text = Object.values(row).join(" ").toLowerCase();
        const hits = [...qWords].filter(w => text.includes(w)).length;
        const recency = row._recency ?? 0.5;
        const weight = row._weight ?? 1.0;
        return (hits / Math.max(qWords.size, 1)) * 0.6 + recency * 0.3 + weight * 0.1;
    }
    pack(sources, query) {
        const scored = [];
        for (const [src, rows] of Object.entries(sources)) {
            for (const row of rows) {
                scored.push([this.score(row, query), { ...row, _src: src }]);
            }
        }
        scored.sort(([a], [b]) => b - a);
        const packed = [];
        let tokens = 0;
        for (const [, row] of scored) {
            const t = Math.floor(JSON.stringify(row).length / 4);
            if (tokens + t > this.budget)
                break;
            packed.push(row);
            tokens += t;
        }
        const totalRows = Object.values(sources).reduce((s, r) => s + r.length, 0);
        return { query, chunks: packed, tokensUsed: tokens,
            sources: Object.keys(sources), totalRows, packedRows: packed.length };
    }
}
// ── Audit Log ─────────────────────────────────────────────────────────────────
export class AuditLog {
    file;
    crypto;
    queue = [];
    timer = null;
    constructor(file) {
        this.file = file;
        this.crypto = getCrypto();
    }
    start() {
        this.timer = setInterval(() => this.flush(), 500);
        this.timer.unref?.(); // don't keep process alive
    }
    stop() {
        if (this.timer)
            clearInterval(this.timer);
        this.flush();
    }
    flush() {
        if (!this.queue.length)
            return;
        const batch = [...this.queue];
        this.queue = [];
        try {
            const existing = this.crypto.readEncrypted(this.file);
            const all = [...(existing.entries ?? []), ...batch].slice(-10_000);
            this.crypto.writeEncrypted(this.file, { entries: all });
        }
        catch { /* non-fatal */ }
    }
    log(event, connector, details = {}, risk = RiskTier.READ) {
        this.queue.push({ ts: Date.now() / 1000, event, connector, risk, ...details });
    }
    readLog() {
        try {
            return this.crypto.readEncrypted(this.file).entries ?? [];
        }
        catch {
            return [];
        }
    }
}
export class LDPEngine {
    dataDir;
    cache;
    consent;
    packer;
    audit;
    connectors = new Map();
    connected = new Set();
    approvalCb;
    stats = {
        messages: 0, discovers: 0, reads: 0,
        cacheHits: 0, cacheMisses: 0,
        consentGranted: 0, consentDenied: 0,
        writeIntents: 0, approved: 0, rejected: 0,
        errors: 0,
    };
    constructor(opts = {}) {
        this.dataDir = opts.dataDir ?? LDP_DIR;
        this.approvalCb = opts.approvalCb ?? null;
        fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
        this.cache = new SchemaCache(path.join(this.dataDir, "schema_cache.enc"));
        this.consent = new ConsentStore(path.join(this.dataDir, "consent.enc"));
        this.audit = new AuditLog(path.join(this.dataDir, "audit.enc"));
        this.packer = new ContextPacker(opts.tokenBudget);
    }
    /** Start background tasks (audit flush). Call before using the engine. */
    start() {
        this.audit.start();
        return this;
    }
    /** Stop background tasks. Call on shutdown. */
    stop() {
        this.audit.stop();
    }
    /** Set approval callback for MEDIUM/HIGH write intents. */
    setApprovalCallback(cb) {
        this.approvalCb = cb;
        return this;
    }
    /** Register a connector. */
    register(connector) {
        this.connectors.set(connector.descriptor.name, connector);
        return this;
    }
    // ── Consent ──────────────────────────────────────────────────────────────────
    /** Returns consent request info. Show this to the user before connect(). */
    requestConsent(name) {
        const c = this.connectors.get(name);
        if (!c)
            return { error: `Unknown connector: ${name}` };
        const d = c.descriptor;
        return {
            connector: name,
            app: d.app,
            permissions: d.permissions,
            dataPaths: d.dataPaths,
            description: d.description,
            fingerprint: getCrypto().hashDescriptor(d),
            prompt: `LDP wants to read your ${d.app} data.\nPermissions: ${d.permissions.join(", ")}\nData stays on your device.\nApprove?`,
        };
    }
    /** Grant consent for a connector. Must be called before connect(). */
    grantConsent(name, grantedBy = "user") {
        const c = this.connectors.get(name);
        if (!c)
            return false;
        this.consent.grant(c.descriptor, grantedBy);
        this.stats.consentGranted++;
        this.audit.log("CONSENT_GRANTED", name, { grantedBy });
        return true;
    }
    /** Revoke consent and disconnect. */
    revokeConsent(name) {
        this.connected.delete(name);
        this.consent.revoke(name);
        this.audit.log("CONSENT_REVOKED", name);
    }
    // ── Connect ───────────────────────────────────────────────────────────────────
    /**
     * Discover + schema in one atomic step.
     * Requires prior grantConsent() unless autoConsent=true (testing only).
     */
    async connect(name, autoConsent = false) {
        const c = this.connectors.get(name);
        if (!c)
            return errorMessage(`Unknown connector: ${name}`);
        if (!this.consent.hasConsent(c.descriptor)) {
            if (autoConsent) {
                this.grantConsent(name, "auto");
            }
            else {
                this.stats.consentDenied++;
                return createMessage(MsgType.ERROR, {
                    error: "consent_required",
                    consentRequest: this.requestConsent(name),
                });
            }
        }
        this.stats.discovers++;
        let found;
        try {
            found = await c.discover();
        }
        catch (e) {
            this.stats.errors++;
            return errorMessage(`discover failed: ${String(e)}`);
        }
        if (!found) {
            this.stats.errors++;
            return errorMessage(`${name}: app data not found on this machine`);
        }
        const fp = getCrypto().hashDescriptor(c.descriptor);
        const cached = this.cache.get(c.descriptor.app, fp);
        if (cached) {
            this.stats.cacheHits++;
        }
        else {
            this.cache.set(c.descriptor.app, fp, await c.schema());
            this.stats.cacheMisses++;
        }
        this.connected.add(name);
        this.stats.messages++;
        this.audit.log("CONNECT", name, { fingerprint: fp });
        return ackMessage({ connector: name, status: "connected",
            cache: cached ? "hit" : "mapped" });
    }
    // ── Query ─────────────────────────────────────────────────────────────────────
    /**
     * Query one or more connected sources.
     * Returns a CONTEXT message with relevance-ranked chunks.
     */
    async query(question, sources) {
        const targets = sources ?? [...this.connected];
        if (!targets.length)
            return errorMessage("No connected sources");
        const raw = {};
        for (const name of targets) {
            if (!this.connected.has(name))
                continue;
            try {
                const rows = await this.connectors.get(name).read(question);
                raw[name] = rows;
                this.stats.reads++;
                this.audit.log("READ", name, { query: question.slice(0, 80), rows: rows.length });
            }
            catch (e) {
                this.stats.errors++;
            }
        }
        const ctx = this.packer.pack(raw, question);
        this.stats.messages++;
        return createMessage(MsgType.CONTEXT, ctx);
    }
    // ── Write Intent ──────────────────────────────────────────────────────────────
    /**
     * Submit a write intent. Engine applies tiered approval.
     * READ/LOW → auto. MEDIUM/HIGH → approvalCb or warn.
     */
    async writeIntent(action, payload, risk, connector = "unknown") {
        const msg = createMessage(MsgType.WRITE_INTENT, { action, ...payload }, { risk, source: connector });
        this.stats.writeIntents++;
        this.audit.log("WRITE_INTENT", connector, { action, risk });
        let approved;
        if (risk === RiskTier.READ || risk === RiskTier.LOW) {
            approved = true;
        }
        else if (this.approvalCb) {
            approved = await this.approvalCb(msg);
        }
        else {
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
    // ── Disconnect ────────────────────────────────────────────────────────────────
    disconnect(name) {
        this.connected.delete(name);
        this.audit.log("DISCONNECT", name);
    }
    // ── Report ────────────────────────────────────────────────────────────────────
    report() {
        return {
            ...this.stats,
            connected: [...this.connected],
            registered: [...this.connectors.keys()],
            consented: this.consent.listConsented(),
        };
    }
}
