#!/usr/bin/env node
/**
 * LDP CLI — ldp start | connect | query | status | audit | list
 */

import { LDPEngine } from "./engine.js";
import { RiskTier } from "./types.js";
import { SyntheticChromeConnector, registerAllSynthetic } from "./index.js";

const [,, cmd, ...rest] = process.argv;

async function start() {
  const { default: engine } = await import("./engine.js")
    .then(() => ({ default: new LDPEngine().start() }));
  console.log("\n  \x1b[1mLDP — Local Data Protocol\x1b[0m v1.0.0");
  console.log("  Local-first · AES-256-GCM · MIT\n");
  console.log("  Commands: connect <app> | query '<question>' | status | audit | list\n");
}

async function connect(app: string) {
  const engine = new LDPEngine().start();
  engine.register(new SyntheticChromeConnector());
  registerAllSynthetic(engine);
  const info = engine.requestConsent(app);
  if ("error" in info) { console.error(`  \x1b[31m✗\x1b[0m ${info.error}`); return; }
  console.log(`\n  LDP wants to read your \x1b[1m${info.app}\x1b[0m data.`);
  console.log(`  Permissions: ${info.permissions.join(", ")}`);
  console.log("  Data stays on this device.\n");
  const ans = await prompt("  Approve? [yes/no]: ");
  if (!["yes","y"].includes(ans.trim().toLowerCase())) { console.log("  Cancelled."); return; }
  engine.grantConsent(app);
  const msg = await engine.connect(app);
  console.log(msg.type === "ACK"
    ? `  \x1b[32m✓\x1b[0m ${app} connected`
    : `  \x1b[31m✗\x1b[0m ${msg.payload.error}`);
}

async function query(question: string) {
  const engine = new LDPEngine().start();
  engine.register(new SyntheticChromeConnector());
  registerAllSynthetic(engine);
  for (const name of ["chrome","spotify","banking","files","whatsapp"]) {
    engine.grantConsent(name);
    await engine.connect(name, true);
  }
  const msg = await engine.query(question);
  if (msg.type === "CONTEXT") {
    const p = msg.payload as Record<string, unknown>;
    console.log(`\n  Sources: ${(p.sources as string[]).join(", ")}`);
    console.log(`  Results: ${p.packedRows}/${p.totalRows} rows\n`);
    const chunks = p.chunks as Record<string, unknown>[];
    for (const chunk of chunks.slice(0, 5)) {
      const { _src, _recency, ...rest } = chunk;
      console.log(`  \x1b[90m[${_src}]\x1b[0m ${JSON.stringify(rest).slice(0, 100)}`);
    }
  } else {
    console.error(`  Error: ${msg.payload.error}`);
  }
}

function status() {
  const r = new LDPEngine().report();
  console.log("\n  \x1b[1mLDP Status\x1b[0m");
  console.log(`  Connected: ${r.connected.join(", ") || "none"}`);
  console.log(`  Reads:     ${r.reads}`);
  console.log(`  Errors:    ${r.errors}\n`);
}

function audit() {
  const entries = new LDPEngine().audit.readLog() as Record<string, unknown>[];
  console.log(`\n  \x1b[1mAudit log\x1b[0m (last ${Math.min(entries.length, 20)})`);
  for (const e of entries.slice(-20)) {
    const ts = new Date((e.ts as number) * 1000).toISOString().slice(11, 19);
    console.log(`  ${ts}  \x1b[90m${String(e.event).padEnd(20)}\x1b[0m  ${e.connector}`);
  }
}

async function prompt(msg: string): Promise<string> {
  process.stdout.write(msg);
  return new Promise(resolve => {
    process.stdin.once("data", d => resolve(d.toString().trim()));
  });
}

async function dashboard() {
  console.log("\n  \x1b[1mOpening LDP Desktop Dashboard\x1b[0m");
  console.log("  If browser doesn't open, visit: \x1b[36mhttp://localhost:8765\x1b[0m\n");
  const { exec } = await import("child_process");
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  exec(`${cmd} http://localhost:8765`);
}

async function main() {
  switch (cmd) {
    case "start":   await start();                    break;
    case "connect": await connect(rest[0] ?? "chrome"); break;
    case "query":   await query(rest.join(" "));      break;
    case "status":  status();                         break;
    case "audit":   audit();                          break;
    case "dashboard": await dashboard();              break;
    default:
      console.log("  Usage: ldp <start|connect|query|status|audit|dashboard>");
  }
}

main().catch(console.error);
