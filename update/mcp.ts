/**
 * LDP → MCP Adapter
 * Exposes all connected LDP sources as MCP-compatible tool definitions.
 *
 * FIX HIGH-04: removed unsafe (this.engine as any).connectors cast.
 * engine.connectors is now declared public readonly in LDPEngine,
 * so the adapter accesses it directly with full type safety.
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
        version:     "2.0.0",
        description: "LDP (Local Data Protocol) MCP adapter. Privacy-first local data access.",
      },
    };
  }

  /** MCP ListTools response — one tool per connected LDP source + cross-source tool. */
  listTools(): { tools: MCPTool[] } {
    const report = this.engine.report();

    const tools: MCPTool[] = report.connected.map(name => {
      /**
       * FIX HIGH-04: was (this.engine as any).connectors?.get(name)
       * Now: this.engine.connectors.get(name)  — fully typed, no cast
       */
      const connector = this.engine.connectors.get(name);
      const desc      = connector?.descriptor;

      return {
        name:        `ldp_${name}_query`,
        description: `Query ${desc?.app ?? name} data via LDP. ${desc?.description ?? ""} Data never leaves your device.`,
        inputSchema: {
          type:       "object",
          properties: {
            question: {
              type:        "string",
              description: `Natural language question about your ${desc?.app ?? name} data`,
            },
            limit: {
              type:        "integer",
              description: "Max rows to return",
              default:     100,
            },
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
      const srcs = args.sources
        ? String(args.sources).split(",").map(s => s.trim()).filter(Boolean)
        : undefined;
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
      sources:      msg.payload.sources,
      returned:     chunks.length,
      total:        msg.payload.totalRows,
      sourceErrors: msg.payload.sourceErrors ?? {},   // MEDIUM-08: surface to MCP callers
      privacy:      "All data read locally — nothing sent to any server",
      data:         chunks,
    };

    return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
  }
}

// ── SECURITY: Secure MCP server factory ──────────────────────────────────────
// CRITICAL (1000-team finding): MCP server MUST bind to 127.0.0.1 only.
// Binding to 0.0.0.0 exposes local data to any machine on the network.
// Each session requires a fresh per-session token.

import * as http    from "node:http";
import * as crypto2 from "node:crypto";

export interface SecureMCPServerOptions {
  /** Port to listen on (default: 7384) */
  port?:    number;
  /** Verbose logging */
  verbose?: boolean;
}

/**
 * Start a hardened MCP HTTP server bound ONLY to 127.0.0.1.
 * Every session requires a Bearer token generated at startup.
 * Returns the server instance and the session token.
 */
export function createSecureMCPServer(
  adapter: MCPAdapter,
  opts:    SecureMCPServerOptions = {},
): Promise<{ server: http.Server; token: string; port: number }> {
  const port  = opts.port  ?? 7384;
  const token = crypto2.randomBytes(32).toString("hex");

  const server = http.createServer((req, res) => {
    // Enforce localhost binding
    const remoteAddr = req.socket.remoteAddress ?? "";
    if (remoteAddr !== "127.0.0.1" && remoteAddr !== "::1" && remoteAddr !== "::ffff:127.0.0.1") {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "LDP MCP only accepts connections from localhost" }));
      return;
    }

    // Enforce session token
    const auth = req.headers.authorization ?? "";
    if (!auth.startsWith("Bearer ") || auth.slice(7) !== token) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing or invalid session token" }));
      return;
    }

    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", async () => {
      try {
        const msg = JSON.parse(body);
        let result: unknown;

        if (msg.method === "initialize") {
          result = adapter.handshake();
        } else if (msg.method === "tools/list") {
          result = adapter.listTools();
        } else if (msg.method === "tools/call") {
          result = await adapter.callTool(msg.params.name, msg.params.arguments ?? {});
        } else {
          result = { error: `Unknown method: ${msg.method}` };
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }));
      } catch (e: any) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: String(e?.message ?? e) }));
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => {
      if (opts.verbose) {
        console.log(`[MCP] Server listening on 127.0.0.1:${port} (localhost only)`);
        console.log(`[MCP] Session token: ${token.slice(0,8)}...`);
      }
      resolve({ server, token, port });
    });
    server.on("error", reject);
  });
}
