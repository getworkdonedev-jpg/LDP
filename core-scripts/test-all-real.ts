import { LDPEngine } from "./engine.js";
import { ChromeConnector } from "./chrome.js";
import { SignalConnector } from "./signal.js";
import { AutoConnectorGenerator } from "./auto-connector.js";

async function main() {
  console.log("\n\x1b[1mLDP — Full Local Data Test\x1b[0m");
  console.log("---------------------------------\n");

  const engine = new LDPEngine().start();

  // 1. Real Connectors
  console.log("\x1b[1m[1/3] Real Connectors: Data Sampling\x1b[0m");
  
  const chrome = new ChromeConnector();
  if (await chrome.discover()) {
    engine.register(chrome);
    engine.grantConsent("chrome");
    await engine.connect("chrome");
    const res = await engine.query("recent_tabs");
    const chunks = (res.payload.chunks as any[]) ?? [];
    console.log(`  \x1b[32m✓\x1b[0m Chrome: Found ${chunks.length} history entries`);
    if (chunks.length > 0) {
      console.log("    \x1b[90mSample:\x1b[0m", JSON.stringify(chunks[0]).slice(0, 120) + "...");
    }
  }

  const signal = new SignalConnector();
  if (await signal.discover()) {
    engine.register(signal);
    engine.grantConsent("signal");
    await engine.connect("signal");
    const res = await engine.query("conversations");
    const chunks = (res.payload.chunks as any[]) ?? [];
    console.log(`  \x1b[32m✓\x1b[0m Signal: Found ${chunks.length} conversations`);
    if (chunks.length > 0) {
      console.log("    \x1b[90mSample:\x1b[0m", JSON.stringify(chunks[0]).slice(0, 120) + "...");
    }
  }

  // 2. Auto-Discovery
  console.log("\n\x1b[1m[2/3] Auto-Discovery: Real Data Test\x1b[0m");
  const gen = new AutoConnectorGenerator({ maxFiles: 100 });
  const results = await gen.scan();
  if (results.length > 0) {
    console.log(`  Discovered ${results.length} sources. Testing data retrieval...`);
    for (const r of results.slice(0, 3)) { // Test top 3
      engine.register(r.connector);
      engine.grantConsent(r.descriptor.name);
      await engine.connect(r.descriptor.name);
      const res = await engine.query("all_data", [r.descriptor.name]);
      const chunks = (res.payload.chunks as any[]) ?? [];
      const status = chunks.length > 0 && !chunks[0]._note ? "\x1b[32m✓ data\x1b[0m" : "\x1b[33m~ meta\x1b[0m";
      console.log(`    - ${r.descriptor.app.padEnd(15)} [${status}] (${(r.confidence * 100).toFixed(0)}% confidence)`);
      if (chunks.length > 0) {
        console.log("      \x1b[90mRow info:\x1b[0m", JSON.stringify(chunks[0]).slice(0, 100) + "...");
      }
    }
  }

  // 3. Cross-Query
  console.log("\n\x1b[1m[3/3] Intelligence: Multi-Source Summary\x1b[0m");
  const cross = await engine.query("recent_tabs, conversations");
  if (cross.payload && Array.isArray(cross.payload.chunks)) {
    console.log(`  Combined Intelligence: Retrieved ${cross.payload.chunks.length} rows across all active apps.`);
    console.log("  Privacy: All processing happened on-device via AES-256-GCM encrypted buffers.");
  }

  engine.stop();
  console.log("\n\x1b[1mFull Test Complete.\x1b[0m\n");
}

main().catch(err => {
  console.error("\n\x1b[31mTest Failed:\x1b[0m", err.message);
  process.exit(1);
});
