/**
 * @ldp-protocol/sdk v3.1.0
 * ========================
 * LDP — Local Data Protocol
 * Privacy-first AI access to personal local data.
 *
 * PACT = Personal AI Context Runtime (product built on this SDK)
 * LDP  = Local Data Protocol         (this open protocol)
 *
 * What's new in v3.1.0:
 *   - GovernedSession — circuit breaker, delegation contracts, attestation penalty
 *   - SystemScanner   — full filesystem walk with AI teacher cascade
 *   - PrivacyEngine   — semantic compression → anonymise → differential privacy
 *   - DistillationEngine — Claude teaches Ollama, local runs forever
 *   - OpenTelemetry observability for governed sessions
 *   - Provenance citations on all query results
 *   - 9 bug fixes in engine, crypto, chrome, signal, mcp, synthetic
 *
 * @example Basic query
 * ```ts
 * import { LDPEngine } from "@ldp-protocol/sdk";
 * import { SyntheticChromeConnector } from "@ldp-protocol/sdk";
 *
 * const engine = new LDPEngine().start();
 *
 * engine.register(new SyntheticChromeConnector());
 * engine.grantConsent("chrome");
 * await engine.connect("chrome");
 *
 * const msg = await engine.query("what sites did I visit most?");
 * console.log(msg.payload);
 * ```
 *
 * @example With privacy for cloud AI
 * ```ts
 * import { PrivacyEngine } from "@ldp-protocol/sdk";
 *
 * const privacy = new PrivacyEngine();
 * const packet  = await privacy.prepareForCloud(rawMessages);
 * const answer  = await callClaude(packet.compressedFacts.join("\n"));
 * console.log(privacy.deanonymise(answer)); // real names restored locally
 * ```
 *
 * @example Knowledge distillation
 * ```ts
 * import { DistillationEngine } from "@ldp-protocol/sdk";
 *
 * const distil = new DistillationEngine({ apiKey: process.env.ANTHROPIC_KEY });
 * await distil.preloadMethods(); // Claude teaches Ollama once — runs locally forever
 *
 * const result = await distil.answer("what was I working on?", contextChunks);
 * // result.cloudUsed === false — running locally from distilled method
 * ```
 *
 * @see https://ldp-protocol.dev
 * @see https://github.com/ldp-protocol/ldp-js
 */

// ── Version (single source of truth: types.ts) ──────────────────────────────
export { LDP_VERSION } from "./types.js";

// ── Core engine (v1 — unchanged public API + 4 bug fixes) ────────────────────
export {
  LDPEngine,
  SchemaCache,
  ConsentStore,
  ContextPacker,
  AuditLog,
} from "./engine.js";
export type { LDPEngineOptions } from "./engine.js";

// ── Protocol types ────────────────────────────────────────────────────────────
export {
  MsgType,
  RiskTier,
  createMessage,
  ackMessage,
  errorMessage,
  isAck,
  isError,
} from "./types.js";
export type {
  LDPMessage,
  ConnectorDescriptor,
  Row,
  SchemaMap,
  ContextResult,
  ConsentRecord,
  ConsentRequest,
  EngineReport,
  ApprovalCallback,
  StreamCallback,
} from "./types.js";

// ── Crypto (CRITICAL-03 fixed) ────────────────────────────────────────────────
export { LDPCrypto, getCrypto, LDP_DIR } from "./crypto.js";

// ── MCP adapter (HIGH-04 fixed) ───────────────────────────────────────────────
export { MCPAdapter }      from "./mcp.js";
export type { MCPTool, MCPToolResult } from "./mcp.js";

// ── Connectors ────────────────────────────────────────────────────────────────
export { ChromeConnector, SyntheticChromeConnector } from "./chrome.js";
export {
  SyntheticSpotifyConnector,
  SyntheticBankingConnector,
  SyntheticFilesConnector,
  SyntheticWhatsAppConnector,
  registerAllSynthetic,
} from "./synthetic.js";

// ── NEW v2.0 — Agentic RAG ────────────────────────────────────────────────────
// export { AgenticRAG }      from "./rag.js";
// export type { Chunk, RAGResult } from "./rag.js";

// ── NEW v2.0 — Memory ─────────────────────────────────────────────────────────
// export { MemoryEngine, HotMemory, WarmMemory, TeamMemory, IntentPredictor } from "./memory.js";
// export type { MemoryEntry, TeamMemoryEntry, HotEntry } from "./memory.js";

// ── NEW v2.0 — Multi-agent ────────────────────────────────────────────────────
// export { SupervisorAgent, routeQuery, assessRisk } from "./agents.js";
// export type { AgentState, AgentType, ActionPlan } from "./agents.js";

// ── NEW v2.0 — Privacy ────────────────────────────────────────────────────────
export { PrivacyEngine, Anonymiser, DifferentialPrivacy } from "./privacy.js";
export type { CompressedContext, MCPContextPacket }        from "./privacy.js";

// ── NEW v2.0 — Knowledge Distillation ────────────────────────────────────────
export { DistillationEngine, classifyTask } from "./distill.js";
export type { DistilledMethod, DistillationResult, DistillationOptions } from "./distill.js";

// ── PACT — the full orchestrator (Goal 1 + 2 + 3 combined) ───────────────────
// export { PACT } from "./pact.js";
// export type { PACTOptions, PACTAnswer } from "./pact.js";

// ── Helpers exported from fixed modules ──────────────────────────────────────
export { extractNamesFromRows }          from "./privacy.js";
export { getLastReadAt, markReadAt }     from "./discover.js";
// ── Self-learning brain ───────────────────────────────────────────────────────
export {
  LDPBrain,
  ApprovalManager,
  KnowledgeBase,
  DecryptionBrain,
  ErrorBrain,
  guessCategory,
} from "./brain.js";

export type {
  BrainOptions,
  BrainDiagnosis,
  BrainErrorType,
  DataCategory,
  DecryptMethod,
  KnownSolution,
} from "./brain.js";

// ── Superposition knowledge base ──────────────────────────────────────────────
export {
  LearnedBase,
  getLearnedBase,
} from "./learned.js";

export type {
  LearnedApp,
  SuperpositionCandidate,
  SuperpositionGroup,
} from "./learned.js";

// ── Full system scanner ───────────────────────────────────────────────────────
export {
  SystemScanner,
} from "./scanner.js";

export type {
  ScannedFile,
  ProcessInfo,
  NetworkConnection,
  ScanResult,
  SystemScannerOptions,
  FileType,
} from "./scanner.js";

// ── Secure MCP server factory ─────────────────────────────────────────────────
export {
  createSecureMCPServer,
} from "./mcp.js";

export type {
  SecureMCPServerOptions,
} from "./mcp.js";
