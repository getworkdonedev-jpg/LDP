/**
 * LDP → MCP Adapter
 * Exposes all connected LDP sources as MCP-compatible tool definitions.
 * Any MCP client (Claude Desktop, Cursor, OpenClaw) can call LDP
 * through the existing MCP protocol with zero client-side changes.
 *
 * @example
 * ```ts
 * import { LDPEngine } from "@ldp-protocol/sdk";
 * import { MCPAdapter } from "@ldp-protocol/sdk/adapters";
 *
 * const engine  = new LDPEngine().start();
 * const adapter = new MCPAdapter(engine);
 *
 * // Drop into any MCP server
 * const tools  = adapter.listTools();
 * const result = await adapter.callTool("ldp_chrome_query", { question: "top sites" });
 * ```
 */

import { MsgType } from "./types.js";
import type { LDPEngine } from "./engine.js";

export interface MCPTool {
  name:        string;
  description: string;
  inputSchema: {
    type:       "object";
    properties: Record<string, { type: string; description: string; default?: unknown }>;
    required:   string[];
  };
}

export interface MCPToolResult {
  content:  Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export class MCPAdapter {
  constructor(private readonly engine: LDPEngine) {}

  /** MCP-compatible server handshake. */
  handshake() {
    return {
      protocolVersion: "2024-11-05",
      capabilities:    { tools: {} },
      serverInfo: {
        name:        "ldp-mcp-adapter",
        version:     "1.0.0",
        description: "LDP (Local Data Protocol) MCP adapter. Privacy-first local data access.",
      },
    };
  }

  /** MCP ListTools response — one tool per connected LDP source + cross-source tool. */
  listTools(): { tools: MCPTool[] } {
    const report = this.engine.report();
    const tools: MCPTool[] = report.connected.map(name => {
      const connector = (this.engine as any).connectors?.get(name);
      const desc      = connector?.descriptor;
      return {
        name:        `ldp_${name}_query`,
        description: `Query ${desc?.app ?? name} data via LDP. ${desc?.description ?? ""} Data never leaves your device.`,
        inputSchema: {
          type:       "object",
          properties: {
            question: { type: "string", description: `Natural language question about your ${desc?.app ?? name} data` },
            limit:    { type: "integer", description: "Max rows to return", default: 100 },
          },
          required: ["question"],
        },
      };
    });

    if (report.connected.length > 1) {
      tools.push({
        name:        "ldp_cross_query",
        description: `Query all connected LDP sources simultaneously (${report.connected.join(", ")}). Cross-source intelligence. Local only.`,
        inputSchema: {
          type:       "object",
          properties: {
            question: { type: "string",  description: "Natural language question" },
            sources:  { type: "string",  description: "Comma-separated sources (default: all)", default: "" },
          },
          required: ["question"],
        },
      });
    }

    return { tools };
  }

  /** MCP CallTool handler. */
  async callTool(name: string, args: Record<string, unknown>): Promise<MCPToolResult> {
    const question = String(args.question ?? "");
    const limit    = Number(args.limit ?? 100);

    let msg;
    if (name === "ldp_cross_query") {
      const srcs = args.sources ? String(args.sources).split(",").map(s => s.trim()).filter(Boolean) : undefined;
      msg = await this.engine.query(question, srcs);
    } else if (name.startsWith("ldp_") && name.endsWith("_query")) {
      const source = name.slice(4, -6);
      msg = await this.engine.query(question, [source]);
    } else {
      return { content: [{ type: "text", text: `Unknown LDP tool: ${name}` }], isError: true };
    }

    if (msg.type === MsgType.ERROR) {
      return { content: [{ type: "text", text: `LDP error: ${msg.payload.error}` }], isError: true };
    }

    const chunks  = (msg.payload.chunks as unknown[])?.slice(0, limit) ?? [];
    const payload = {
      sources:   msg.payload.sources,
      returned:  chunks.length,
      total:     msg.payload.totalRows,
      privacy:   "All data read locally — nothing sent to any server",
      data:      chunks,
    };

    return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
  }
}
