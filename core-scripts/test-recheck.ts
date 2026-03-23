import { SystemScanner } from "./scanner.js";
import { KnowledgeBase } from "./brain.js";
import * as fs from "fs";

async function run() {
  const kb = new KnowledgeBase();
  const p = "/Users/karthikperumalla/Library/Group Containers/243LU875E5.groups.com.apple.podcasts/Documents/MTLibrary.sqlite";
  const entry = kb.lookup(p);
  if (!entry) {
    console.log("No Apple Podcasts entry!");
    return;
  }
  
  // Set fake schemaHash to trigger an update
  entry.schemaHash = "fakehash123";
  kb.learn(entry, true);
  console.log("Added fake schemaHash to Apple Podcasts.");
  
  // Run scan round 1: should detect mismatch and queue it
  console.log("\n--- SCAN ROUND 1: Detect Mismatch ---");
  let scanner = new SystemScanner({ maxDepth: 4, verbose: false, apiKey: "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" });
  await scanner.run();
  
  const q = new KnowledgeBase().getRecheckQueue();
  console.log("Recheck Queue after Round 1:", q);
  
  // Run scan round 2: should process queue and call Claude
  console.log("\n--- SCAN ROUND 2: Process Queue & Re-identify ---");
  scanner = new SystemScanner({ maxDepth: 4, verbose: true, apiKey: "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" });
  await scanner.run();
  
  const finalKb = new KnowledgeBase();
  const updated = finalKb.lookup(p);
  console.log("\n--- RESULTS ---");
  console.log("Updated entry schemaHash:", updated?.schemaHash);
  console.log("Updated entry tableCount:", updated?.tableCount);
  console.log("Queue length after round 2:", finalKb.getRecheckQueue().length);
}

run().catch(console.error);
