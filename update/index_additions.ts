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
