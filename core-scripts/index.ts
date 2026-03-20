/**
 * @ldp-protocol/sdk
 * ==================
 * LDP — Local Data Protocol
 * Privacy-first AI access to personal local data.
 *
 * Use MCP for cloud tools. Use LDP for local data.
 *
 * @example Basic usage
 * ```ts
 * import { LDPEngine, RiskTier } from "@ldp-protocol/sdk";
 * import { SyntheticChromeConnector } from "@ldp-protocol/sdk/connectors";
 *
 * const engine = new LDPEngine().start();
 * engine.register(new SyntheticChromeConnector());
 * engine.grantConsent("chrome");
 *
 * await engine.connect("chrome");
 * const result = await engine.query("what sites did I visit most this week");
 * // result.payload.chunks — your data, never left your machine
 * ```
 *
 * @example With MCP adapter
 * ```ts
 * import { LDPEngine } from "@ldp-protocol/sdk";
 * import { MCPAdapter } from "@ldp-protocol/sdk/adapters";
 *
 * const engine  = new LDPEngine().start();
 * const adapter = new MCPAdapter(engine);
 * const tools   = adapter.listTools(); // drop into any MCP server
 * ```
 *
 * @example Build your own connector
 * ```ts
 * import type { BaseConnector, ConnectorDescriptor } from "@ldp-protocol/sdk/connectors";
 *
 * class MyAppConnector implements BaseConnector {
 *   descriptor: ConnectorDescriptor = {
 *     name: "myapp", app: "My App", version: "1.0",
 *     dataPaths: ["~/.myapp/data.db"],
 *     permissions: ["data.read"],
 *     namedQueries: {},
 *     description: "My app local data",
 *   };
 *   async discover() { return true; }
 *   async schema()   { return { data: { id: "row id" } }; }
 *   async read(query: string) { return []; }
 * }
 * ```
 *
 * @see https://ldp-protocol.dev
 * @see https://github.com/ldp-protocol/ldp-js
 */

export const LDP_VERSION = "1.0.0" as const;

// ── Core engine — everything a developer needs ────────────────────────────────
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

// ── Crypto ────────────────────────────────────────────────────────────────────
export { LDPCrypto, getCrypto, LDP_DIR } from "./crypto.js";

// ── Adapters (re-export for convenience) ──────────────────────────────────────
export { MCPAdapter } from "./mcp.js";
export type { MCPTool, MCPToolResult } from "./mcp.js";
