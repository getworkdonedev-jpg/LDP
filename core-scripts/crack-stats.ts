import { PACT } from "./new/pact.js";
import { APP_TARGETS } from "./discover.js";
import { AutoConnectorGenerator } from "./auto-connector.js";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

async function main() {
  console.log("\n\x1b[1mLDP — Deep Discovery & Decryption Report\x1b[0m");
  console.log("-------------------------------------------\n");

  // 1. Static Discovery
  console.log("\x1b[1m[1/2] Static Path Analysis (Core Apps)\x1b[0m");
  const pact = await PACT.start({ verbose: false });
  const report = await pact.report() as any;
  const connected = report.connected || [];

  const platform = process.platform as NodeJS.Platform;
  let staticFound = 0;
  let staticCracked = 0;
  let staticLocked = 0;
  let staticMissing = 0;
  const pad = (str: string, n: number) => str.padEnd(n);

  const results: Array<{ name: string; status: "cracked" | "locked" | "missing" | "no_data" }> = [];

  for (const target of APP_TARGETS) {
    const globs = target.globs[platform] || target.globs["linux"] || [];
    let status: "cracked" | "locked" | "missing" | "no_data" = "missing";

    for (const g of globs) {
      const expanded = g.replace(/^~/, os.homedir());
      if (fs.existsSync(expanded)) {
        status = connected.includes(target.name) ? "cracked" : "no_data";
        break;
      }
      
      // Check if parent directory is locked (Full Disk Access)
      const parent = expanded.split("*")[0].replace(/\/[^/]*$/, "");
      try {
        if (fs.existsSync(parent)) {
          fs.readdirSync(parent);
        }
      } catch (e: any) {
        if (e.code === "EACCES" || e.message?.includes("permitted")) {
          status = "locked";
        }
      }
    }

    // Fallback: If still missing, check if App is even installed
    if (status === "missing") {
      const appPath = `/Applications/${target.app}.app`;
      if (fs.existsSync(appPath)) {
        status = "locked"; // If app exists but data doesn't, it's usually a permission/path issue
      }
    }

    if (status === "cracked") { staticFound++; staticCracked++; }
    else if (status === "locked") { staticFound++; staticLocked++; }
    else if (status === "no_data") { staticFound++; }
    else { staticMissing++; }

    results.push({ name: target.app, status });
  }

  console.log(`  Static Targets Found:     ${staticFound}`);
  console.log(`  Successfully Connected:   ${staticCracked}`);
  console.log(`  Locked (Permission):      ${staticLocked}`);
  
  if (staticLocked > 0) {
    console.log("\n  \x1b[33m[!] Action Required: Full Disk Access needed for:\x1b[0m");
    results.filter(r => r.status === "locked").forEach(r => console.log(`    - ${r.name}`));
  }

  // 2. Deep Heuristic Discovery
  console.log("\n\x1b[1m[2/2] Deep Heuristic Scanning (Auto-Discovery)\x1b[0m");
  console.log("  Scanning filesystem for unknown databases (FULL EXHAUSTIVE — up to 5000 files)...");

  const gen = new AutoConnectorGenerator({
    maxFiles: 5000,
    maxDepth: 25,
    showLowPriority: true,
    allowDuplicates: true,
    fullExhaustive: true,
    allowLowConfidence: true,
  });
  const deepResults = await gen.scan();

  const totalApps = staticFound + deepResults.length;
  // Note: Auto-connector results only include those that were successfully scanned/read
  const totalCracked = staticCracked + deepResults.length;

  console.log(`  Deep Sources Discovered: ${deepResults.length}`);
  if (deepResults.length > 0) {
    console.log("  Sample Unique Deep Sources (Heuristic):");
    const uniqueDeep = Array.from(new Set(deepResults.map(r => r.descriptor.app)));
    uniqueDeep.slice(0, 15).forEach(name => {
      console.log(`    - ${pad(name, 25)} [✓ CONNECTED]`);
    });
  }

  const crackRate = totalApps > 0 ? (totalCracked / totalApps) * 100 : 0;

  console.log("\n" + "-".repeat(55));
  console.log(`\x1b[1mFinal Intelligence Coverage:\x1b[0m`);
  console.log(`  Total Apps Discovered:     ${totalApps}`);
  console.log(`  Successfully Connected:    ${totalCracked}`);
  console.log(`  \x1b[1m\x1b[4mDiscovery Efficiency:\x1b[0m      \x1b[1m\x1b[32m${crackRate.toFixed(1)}%\x1b[0m`);
  console.log("-".repeat(55) + "\n");

  pact.stop();
}

main().catch(console.error);
