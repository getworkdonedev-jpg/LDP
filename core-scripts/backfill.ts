import { KnowledgeBase } from "./brain.js";
import { readTables, readDensity } from "./scanner.js";
import * as fs from "fs";
import * as crypto from "crypto";

async function run() {
  const kb = new KnowledgeBase();
  let updated = 0;

  for (const [key, item] of (kb as any).store.entries()) {
    if (key.startsWith("static_")) continue;
    
    if (item.filePath === "ai_identified") {
      (kb as any).store.delete(key);
      updated++;
      continue;
    }

    if (!item.schemaHash && fs.existsSync(item.filePath)) {
      try {
        const tables = readTables(item.filePath);
        if (tables.length > 0) {
          item.schemaHash = crypto.createHash("md5").update(tables.slice().sort().join(",")).digest("hex");
          item.tableCount = tables.length;
          item.rowCountSnapshot = (item as any).totalRows ?? 0;
          item.learnedAt = item.solvedAt || Date.now();
          item.needsRecheck = false;
          item.source = item.confidence === 1.0 ? "heuristic" : "claude"; 
          updated++;
          console.log(`Backfilled: ${item.appName} (${key})`);
        } else {
             // For files that are not SQLite (like JSON or others) we just mark them with dummy data so they aren't 'MISSING'
             item.schemaHash = "not_sqlite";
             item.tableCount = 0;
             item.rowCountSnapshot = 0;
             item.learnedAt = item.solvedAt || Date.now();
             item.needsRecheck = false;
             item.source = "heuristic";
             updated++;
        }
      } catch (e) {
        console.error("Error reading", item.filePath, e);
      }
    } else if (!item.schemaHash && !fs.existsSync(item.filePath)) {
         item.schemaHash = "file_not_found";
         item.tableCount = 0;
         item.rowCountSnapshot = 0;
         item.learnedAt = item.solvedAt || Date.now();
         item.needsRecheck = false;
         item.source = "heuristic";
         updated++;
    }
  }

  if (updated > 0) {
    kb.save();
    console.log(`Backfill complete. Updated ${updated} entries.`);
  } else {
    console.log("Nothing to backfill.");
  }
}

run().catch(console.error);
