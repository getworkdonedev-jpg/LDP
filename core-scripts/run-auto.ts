import { SystemScanner } from "./scanner.js";
import * as path from "node:path";

async function main() {
  console.log("\n[LDP] Starting AI-Powered Auto-Discovery (Phase 14)...");
  console.log("====================================================\n");

  const scanner = new SystemScanner({ verbose: true, maxFiles: 5000 });
  const result = await scanner.run();

  console.log("\n[LDP] SCAN SUMMARY:");
  console.log("---------------------------------------------------------------------------------------------------");
  console.log(`${"APP NAME".padEnd(25)} | ${"ROWS".padEnd(10)} | ${"CONFIDENCE".padEnd(12)} | ${"STATUS".padEnd(15)} | ${"SOURCE PATH"}`);
  console.log("---------------------------------------------------------------------------------------------------");

  for (const db of result.databases) {
    const status = db.confidence >= 0.8 ? "Auto-Connected" : (db.confidence >= 0.5 ? "Pending Approval" : "Skipped");
    const rowStr = db.totalRows ? db.totalRows.toLocaleString() : "0";
    console.log(`${db.appName.padEnd(25)} | ${rowStr.padEnd(10)} | ${(db.confidence.toFixed(2)).padEnd(12)} | ${status.padEnd(15)} | ${db.filePath}`);
  }

  // Handle static connectors
  for (const df of result.dataFiles) {
     const status = df.confidence >= 0.8 ? "Auto-Connected" : "Pending";
     console.log(`${df.appName.padEnd(25)} | ${"N/A".padEnd(10)} | ${(df.confidence.toFixed(2)).padEnd(12)} | ${status.padEnd(15)} | ${df.filePath}`);
  }

  console.log("---------------------------------------------------------------------------------------------------\n");
  console.log(`Scan completed in ${result.durationMs}ms.`);
  console.log(`Discovered: ${result.databases.length} databases, ${result.dataFiles.length} static data sources.`);
  console.log("Knowledge saved to brain_knowledge.json.\n");
}

main().catch(console.error);
