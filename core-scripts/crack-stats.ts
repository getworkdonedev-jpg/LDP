import { PACT } from "./new/pact.js";
import { APP_TARGETS, resolveGlob } from "./discover.js";

async function main() {
  console.log("\n\x1b[1mLDP — Discovery & Decryption Reliability Report\x1b[0m");
  console.log("-----------------------------------------------\n");

  // Verbose start to see discovery details
  const pact = await PACT.start({ verbose: true });
  const report = await pact.report() as any;
  const connected = report.connected || []; // Successfully connected/decrypted connectors

  const platform = process.platform as NodeJS.Platform;
  
  let totalFound = 0;
  let totalCracked = 0;
  
  const pad = (str: string, n: number) => str.padEnd(n);
  
  console.log(`${pad("Application", 25)} ${pad("Exist?", 10)} ${pad("Status", 15)}`);
  console.log("-".repeat(55));

  for (const target of APP_TARGETS) {
    const globs = target.globs[platform] || target.globs["linux"] || [];
    let exists = false;
    
    for (const g of globs) {
      const p = resolveGlob(g);
      if (p) {
        exists = true;
        break;
      }
    }

    if (exists) {
      totalFound++;
      const isConnected = connected.includes(target.name);
      if (isConnected) totalCracked++;
      
      const statusText = isConnected ? "\x1b[32m✓ CONNECTED\x1b[0m" : "\x1b[31m✖ LOCKED\x1b[0m";
      console.log(`${pad(target.app, 25)} ${pad("YES", 10)} ${pad(statusText, 15)}`);
    }
  }

  const crackRate = totalFound > 0 ? (totalCracked / totalFound) * 100 : 0;

  console.log("\n" + "-".repeat(55));
  console.log(`\x1b[1mSummary Analysis:\x1b[0m`);
  console.log(`  Local Data Sources Found:  ${totalFound}`);
  console.log(`  Decrypted / Connected:     ${totalCracked}`);
  console.log(`  \x1b[1m\x1b[4mCracking Efficiency:\x1b[0m       \x1b[1m\x1b[32m${crackRate.toFixed(1)}%\x1b[0m`);
  console.log("-".repeat(55) + "\n");

  pact.stop();
}

main().catch(console.error);
