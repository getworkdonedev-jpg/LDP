/**
 * PACT — Personal AI Context Runtime
 * ====================================
 * The single entry point that wires all three LDP goals together.
 *
 * Goal 1 — Auto-discover + auto-decrypt all local data
 * Goal 2 — Knowledge distillation (Claude teaches local Ollama once)
 * Goal 3 — 3-layer privacy (compress → anonymise → DP noise)
 *
 * Result — Claude-level answers. Zero raw data to cloud.
 *
 * Developer writes TWO lines:
 *
 *   import { PACT } from "@ldp-protocol/sdk/pact";
 *   const pact = await PACT.start({ verbose: true });
 *
 *   const answer = await pact.ask("what have I been working on?");
 *   // → Claude-level answer, drawn from git + VS Code + shell history
 *   //   raw data never left your machine
 *
 * How it works internally:
 *
 *   1. autoDiscover()  — FingerprintAgent, DecryptAgent, SchemaAgent
 *                        registers all found apps automatically
 *                        delta sync: only reads what changed since last run
 *
 *   2. ask(question)   — routes to correct connectors via multi-agent
 *                        reads only new delta rows (not full history each time)
 *                        extracts names automatically
 *
 *   3. privacy.prepareForCloud()
 *                      — compress 1000 rows → 20 semantic facts
 *                        anonymise: Person A, Person B (no real names)
 *                        differential privacy noise on numbers
 *                        Claude ONLY sees the anonymised compressed packet
 *
 *   4. distill.answer()
 *                      — Mode A: local Ollama handles it (~48% of queries)
 *                        Mode B: distilled method from previous teach session
 *                        Mode C: Claude teaches Ollama the reasoning method
 *                                once, runs locally forever after
 *
 *   5. deanonymise()   — restore real names locally before showing user
 */

import type { LDPEngine }          from "./engine.js";
import type { DiscoveryResult }    from "./discover.js";
import type { DistillationResult } from "./distill.js";
import type { MCPContextPacket }   from "./privacy.js";
import type { AgentState }         from "./agents.js";

// Dynamic imports keep startup fast — only load what each ask() needs
async function getEngine()    { const { LDPEngine }         = await import("./engine.js");    return LDPEngine; }
async function getDiscover()  { const m = await import("./discover.js");  return m; }
async function getPrivacy()   { const { PrivacyEngine }     = await import("./privacy.js");   return PrivacyEngine; }
async function getDistill()   { const { DistillationEngine } = await import("./distill.js");  return DistillationEngine; }
async function getSupervisor(){ const { SupervisorAgent }   = await import("./agents.js");    return SupervisorAgent; }
async function getRAG()       { const { AgenticRAG }        = await import("./rag.js");       return AgenticRAG; }
async function getMemory()    { const { MemoryEngine }      = await import("./memory.js");    return MemoryEngine; }

// ── Options ───────────────────────────────────────────────────────────────────

export interface PACTOptions {
  /** Anthropic API key for cloud AI calls. Optional — local Ollama works without it. */
  anthropicKey?: string;
  /** Log each step. Default false. */
  verbose?: boolean;
  /** Skip these app names during discovery. */
  skipApps?: string[];
  /** Force re-read all data even if unchanged. Default false (delta sync). */
  forceRescan?: boolean;
  /** Preload all distillation methods on startup (one Claude call per task type). Default false. */
  preloadDistillation?: boolean;
  /** Differential privacy budget. Lower = more private, less accurate. Default 1.0. */
  privacyEpsilon?: number;
}

// ── Answer ────────────────────────────────────────────────────────────────────

export interface PACTAnswer {
  answer:        string | null;
  mode:          "local_cascade" | "local_distilled" | "cloud_taught" | "no_answer";
  cloudUsed:     boolean;
  sourcesRead:   string[];
  rowsFound:     number;
  compressionRatio: number;
  confidence:    number;
  durationMs:    number;
}

// ── Internal state ────────────────────────────────────────────────────────────

interface PACTState {
  engine:     InstanceType<Awaited<ReturnType<typeof getEngine>>>;
  privacy:    InstanceType<Awaited<ReturnType<typeof getPrivacy>>>;
  distill:    InstanceType<Awaited<ReturnType<typeof getDistill>>>;
  supervisor: InstanceType<Awaited<ReturnType<typeof getSupervisor>>>;
  rag:        InstanceType<Awaited<ReturnType<typeof getRAG>>>;
  memory:     InstanceType<Awaited<ReturnType<typeof getMemory>>>;
  connected:  string[];
  opts:       PACTOptions;
}

// ── PACT class ────────────────────────────────────────────────────────────────

export class PACT {
  private constructor(private readonly state: PACTState) {}

  // ── Factory — the only entry point ──────────────────────────────────────────

  /**
   * Start PACT. Discovers all local apps automatically.
   * Returns a PACT instance ready to answer questions.
   *
   * @example
   * const pact = await PACT.start({ verbose: true });
   * const answer = await pact.ask("what was I working on yesterday?");
   */
  static async start(opts: PACTOptions = {}): Promise<PACT> {
    const t0 = Date.now();

    if (opts.verbose) console.log("\n[PACT] Starting...");

    // 1. Boot LDP engine
    const EngineClass     = await getEngine();
    const engine          = new EngineClass().start();

    // 2. Boot all AI subsystems
    const PrivacyClass    = await getPrivacy();
    const DistillClass    = await getDistill();
    const SupervisorClass = await getSupervisor();
    const RAGClass        = await getRAG();
    const MemoryClass     = await getMemory();

    const privacy    = new PrivacyClass(opts.privacyEpsilon ?? 1.0);
    const distill    = new DistillClass({ apiKey: opts.anthropicKey });
    const rag        = new RAGClass();
    const memory     = new MemoryClass();
    const supervisor = new SupervisorClass({ rag, memory });

    // 3. Auto-discover all local apps (Goal 1)
    const { autoConnect } = await getDiscover();
    const discovery = await autoConnect(engine, {
      verbose:     opts.verbose,
      skip:        opts.skipApps,
      forceRescan: opts.forceRescan,
    });

    if (opts.verbose) {
      console.log(`[PACT] Connected: ${discovery.connected.join(", ") || "none"}`);
      if (discovery.failed.length > 0) {
        console.log(`[PACT] Skipped: ${discovery.failed.map(f => f.path.split("/").at(-2)).join(", ")}`);
      }
    }

    // 4. Optionally preload distillation methods (Goal 2)
    if (opts.preloadDistillation && opts.anthropicKey) {
      if (opts.verbose) console.log("[PACT] Preloading distillation methods...");
      const count = await distill.preloadMethods();
      if (opts.verbose) console.log(`[PACT] ${count} new reasoning methods taught to local model`);
    }

    const state: PACTState = {
      engine, privacy, distill, supervisor, rag, memory,
      connected: discovery.connected,
      opts,
    };

    if (opts.verbose) console.log(`[PACT] Ready in ${Date.now() - t0}ms\n`);
    return new PACT(state);
  }

  // ── ask() — the main method ──────────────────────────────────────────────────

  /**
   * Ask anything about your local data.
   * All 3 goals execute automatically in the right order.
   *
   * @example
   * const answer = await pact.ask("what sites did I waste time on?");
   * const answer = await pact.ask("summarise my Signal conversations this week");
   * const answer = await pact.ask("what was the last git commit I made?");
   */
  async ask(question: string): Promise<PACTAnswer> {
    const t0 = Date.now();
    const { engine, privacy, distill, supervisor, rag, opts } = this.state;

    if (opts.verbose) console.log(`[PACT] Question: "${question}"`);

    // ── Step 1: Route + read raw data ─────────────────────────────────────────

    // Supervisor routes to correct connectors (work/social/finance/web/etc)
    const agentState = await supervisor.run(question);
    const sources    = agentState.sourcesSearched ?? [];

    // Also pull directly from LDP engine for full coverage
    let engineRows: Array<Record<string, unknown>> = [];
    if (this.state.connected.length > 0) {
      const msg = await engine.query(question, this.state.connected);
      if (msg.type === "CONTEXT") {
        engineRows = (msg.payload.chunks as Array<Record<string, unknown>>) ?? [];
      }
    }

    // Combine: agent context chunks + engine rows
    const contextChunks = [
      ...agentState.contextChunks.map(c => c.text),
      ...engineRows.slice(0, 200).map(r =>
        Object.values(r)
          .filter(v => v !== null && typeof v !== "object")
          .join(" ")
          .slice(0, 200)
      ),
    ].filter(Boolean);

    const rowCount = engineRows.length + agentState.contextChunks.length;
    if (opts.verbose) console.log(`[PACT] Read ${rowCount} rows from ${sources.length} sources`);

    // ── Step 2: Privacy pipeline (Goal 3) ────────────────────────────────────
    // compress → anonymise (auto-extracts names) → DP noise
    // Claude ONLY sees the packet — never the raw rows

    const numericalContext: Record<string, number> = {};
    for (const row of engineRows.slice(0, 500)) {
      for (const [k, v] of Object.entries(row)) {
        if (typeof v === "number") {
          numericalContext[k] = (numericalContext[k] ?? 0) + v;
        }
      }
    }

    const packet = await privacy.prepareForCloud(
      contextChunks,
      numericalContext,
      [],              // knownNames — auto-extracted from rawRows below
      agentState.memoryFacts.map(f => ({ key: f.key, value: f.value })),
      engineRows,      // rawRows → names extracted automatically (Fix 3)
    );

    if (opts.verbose) {
      console.log(`[PACT] Privacy: ${packet.originalItemCount} items → ${packet.compressedFacts.length} facts (${Math.round((1 - packet.compressionRatio) * 100)}% compressed)`);
    }

    // ── Step 3: Distillation (Goal 2) ────────────────────────────────────────
    // Cascade → distilled method → teach Claude once → run locally forever
    // Claude receives ONLY the anonymised compressed facts

    const distillContext = [
      ...packet.compressedFacts,
      ...packet.userFacts.map(f => `${f.key}: ${f.value}`),
    ];

    const distillResult = await distill.answer(question, distillContext);

    if (opts.verbose) {
      console.log(`[PACT] Distill mode: ${distillResult.mode} | cloud: ${distillResult.cloudUsed}`);
    }

    // ── Step 4: Deanonymise answer before showing user ────────────────────────
    // Real names restored locally — never went to cloud

    const rawAnswer    = distillResult.answer;
    const finalAnswer  = rawAnswer ? privacy.deanonymise(rawAnswer) : null;

    // ── Step 5: Store in memory for future context ────────────────────────────
    if (finalAnswer) {
      this.state.memory.addContext("assistant", finalAnswer);
      this.state.memory.intent.record(question.slice(0, 80));
    }

    const mode = distillResult.mode === "cascade_local"   ? "local_cascade"
               : distillResult.mode === "distil_local"    ? "local_distilled"
               : distillResult.mode === "distil_new"      ? "cloud_taught"
               : "no_answer";

    return {
      answer:           finalAnswer,
      mode,
      cloudUsed:        distillResult.cloudUsed,
      sourcesRead:      this.state.connected,
      rowsFound:        rowCount,
      compressionRatio: packet.compressionRatio,
      confidence:       agentState.confidence,
      durationMs:       Date.now() - t0,
    };
  }

  // ── Convenience methods ───────────────────────────────────────────────────

  /**
   * Morning briefing — fully local, no cloud needed.
   */
  briefing(): string {
    return this.state.memory.briefing();
  }

  /**
   * What apps are connected.
   */
  get connected(): string[] {
    return [...this.state.connected];
  }

  /**
   * Engine report — reads, errors, consent status.
   */
  report() {
    return this.state.engine.report();
  }

  /**
   * GDPR erase — deletes all memory tiers atomically.
   */
  erase(): Record<string, boolean> {
    return this.state.memory.erase("all");
  }

  /**
   * Teach local model a new reasoning method for a task type.
   * Only needed if you want to pre-train before users ask questions.
   */
  async teach(taskType: string): Promise<boolean> {
    const stats = this.state.distill.stats();
    if (stats.distilledMethods.taskTypes.includes(taskType)) return true;
    return (await this.state.distill.preloadMethods()) > 0;
  }

  /**
   * Rediscover apps — useful after installing new apps.
   */
  async rediscover(forceRescan = false): Promise<DiscoveryResult> {
    const { autoConnect } = await getDiscover();
    const result = await autoConnect(this.state.engine, {
      verbose:     this.state.opts.verbose,
      forceRescan,
    });
    this.state.connected.push(
      ...result.connected.filter(n => !this.state.connected.includes(n)),
    );
    return result;
  }

  /**
   * Stop background tasks cleanly.
   */
  stop(): void {
    this.state.engine.stop();
  }
}

// ── Convenience factory ───────────────────────────────────────────────────────

export type { DiscoveryResult, PACTAnswer, PACTOptions };
