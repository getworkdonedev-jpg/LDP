import { createSecureMCPServer, MCPAdapter } from "./mcp.js";
import { LDPEngine } from "./engine.js";

async function main() {
  const engine = new LDPEngine().start();
  const adapter = new MCPAdapter(engine);
  
  console.error(`[LDP] Starting Secure MCP Server...`);

  // The factory starts the server immediately and returns the generated token
  const { token, port } = await createSecureMCPServer(adapter, {
    port: 7384,
    verbose: true
  });

  console.log(`\n─────────────────────────────────────────────────────`);
  console.log(`🚀 SECURE MCP SERVER RUNNING`);
  console.log(`─────────────────────────────────────────────────────`);
  console.log(`  Port:  ${port}`);
  console.log(`  Token: ${token}`);
  console.log(`─────────────────────────────────────────────────────`);
  console.log(`\nUpdate your ~/.cursor/mcp.json to use this server.`);
}

main().catch(err => {
  console.error(`\n❌ MCP Server Error:`, err);
  process.exit(1);
});
