import { KnowledgeBase } from "./brain.js";
import * as fs from "node:fs";

async function main() {
  const kb = new KnowledgeBase();
  const rawTools = kb.list();
  const seenNames = new Set<string>();
  const finalTools: any[] = [];

  // Core apps we ALWAYS want to keep
  const coreApps = ["imessage", "notes", "safari", "whatsapp", "signal", "telegram", "calendar", "contacts", "mail", "vscode", "cursor", "git", "shell", "health", "system_health"];

  for (const sol of rawTools) {
    let name = sol.appKey;
    
    // Grouping / Deduping logic
    if (name.includes("_state_vscdb")) name = "vscode_workspaces";
    if (name.includes("_global_storage")) name = "vscode_global_storage";
    if (name.includes("whatsapp") || sol.appName.toLowerCase().includes("whatsapp")) name = "whatsapp";

    // Clean up names
    name = name.replace(/^static_|^path_|^auto_/, "");
    name = name.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    if (name.startsWith("apple_")) name = name.replace("apple_", "");
    
    // Aggressive Noise Filter (Problem 3)
    const noise = ["tomb", "backup", "cache", "thumbnail", "authorization", "akd", "siri", "heavy_ad", "tipkit", "dock", "vscdb", "metadata", "plist", "json", "coredatabackend"];
    
    const isCore = coreApps.some(a => name.includes(a) || sol.appName.toLowerCase().includes(a));
    const isNoise = noise.some(n => name.includes(n) || sol.appName.toLowerCase().includes(n));
    
    // Skip noise unless it's a core app we forced inclusion for
    if (isNoise && !isCore) continue;
    
    // Skip generic plists/jsons/low-conf unless core
    if ((sol.appKey.startsWith("static_") && (sol.appKey.includes("plist") || sol.appKey.includes("json"))) && !isCore) continue;
    if (name.startsWith("unknown") && sol.confidence < 0.5) continue;

    if (seenNames.has(name)) continue;
    seenNames.add(name);

    finalTools.push({
      name,
      app: sol.appName,
      path: sol.filePath,
      method: sol.method,
      category: sol.category || "other",
      confidence: sol.confidence
    });
  }

  // Sort: Core first, then by confidence
  finalTools.sort((a,b) => {
    const aCore = coreApps.some(c => a.name.includes(c)) ? 1 : 0;
    const bCore = coreApps.some(c => b.name.includes(c)) ? 1 : 0;
    if (aCore !== bCore) return bCore - aCore;
    return b.confidence - a.confidence;
  });

  console.log(JSON.stringify(finalTools));
}

main().catch(() => process.exit(1));
