import * as path from "node:path";
import * as os from "node:os";
import { SystemScanner } from "./scanner.js";
import { KnowledgeBase } from "./brain.js";

async function run() {
  const kb = new KnowledgeBase();
  const scanner = new SystemScanner({ apiKey: "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", verbose: true });

  const p = path.join(os.homedir(), "Library/Group Containers/243LU875E5.groups.com.apple.podcasts/Documents/MTLibrary.sqlite");
  const entry = kb.lookup(p);
  if (!entry) {
    console.log("No entry found!");
    return;
  }
  
  console.log("Adding to queue with schema_changed...");
  kb.queueRecheck({ path: p, reason: "schema_changed", priority: "high", scheduledFor: "next_run" });
  
  console.log("Queued:", kb.getRecheckQueue());

  console.log("Processing queue...");
  await (scanner as any).processRecheckQueue(kb, (scanner as any).opts.apiKey);
  
  const updated = kb.lookup(p);
  console.log("Queue length after:", kb.getRecheckQueue().length);
  console.log("New Source:", updated?.source);
  console.log("New SchemaHash:", updated?.schemaHash);
}

run().catch(console.error);
