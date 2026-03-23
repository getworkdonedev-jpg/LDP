import { SystemScanner } from "./scanner.js";
import { KnowledgeBase } from "./brain.js";

async function run() {
  const apiKey = "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";
  const kb = new KnowledgeBase();
  const p = "/Users/karthikperumalla/Library/Group Containers/243LU875E5.groups.com.apple.podcasts/Documents/MTLibrary.sqlite";
  
  // 1 & 2: Simulate app update
  const entry = kb.lookup(p);
  if (!entry) {
    console.log("Entry not found."); return;
  }
  entry.schemaHash = "fake_schema_hash_from_update";
  kb.learn(entry, true);
  console.log("1. Simulated app update by altering schema hash to 'fake_schema_hash_from_update'.");

  // 3 & 4 & 5: Run scan to detect mismatch and queue
  console.log("\n2. Simulating background scan finding the mismatch...");
  const scanner1 = new SystemScanner({ maxDepth: 2, verbose: false, apiKey: "" }); // apiKey empty so it doesn't process queue right away
  await scanner1.run();
  
  const q = new KnowledgeBase().getRecheckQueue();
  console.log("\n3. Queue after scan:");
  console.log(q);

  // 6 & 7: Run startup again where it processes the queue
  console.log("\n4. Simulating next startup (this should process the queue)...");
  const scanner2 = new SystemScanner({ maxDepth: 1, verbose: true, apiKey });
  await scanner2.run();

  const finalKb = new KnowledgeBase();
  const finalEntry = finalKb.lookup(p);
  console.log("\n5. Verification Results:");
  console.log("Old Fake Hash:", "fake_schema_hash_from_update");
  console.log("Final Restored Real Hash:", finalEntry?.schemaHash);
  console.log("Queue Length:", finalKb.getRecheckQueue().length);
}

run().catch(console.error);
