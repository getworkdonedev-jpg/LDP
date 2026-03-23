import { KnowledgeBase } from "./brain.js";
import * as fs from "node:fs";

async function main() {
  const kb = new KnowledgeBase();
  const rawTools = kb.list();
  const seenNames = new Set<string>();
  const finalTools: any[] = [];

  // Core apps we ALWAYS want to keep (Fix 1 & 2)
  const coreAppsMap: Record<string, string> = {
    "chrome":     "chrome_history",
    "shell":      "shell_history",
    "git":        "git_log",
    "imessage":   "imessage",
    "notes":      "notes",
    "safari":     "safari_history",
    "calendar":   "calendar",
    "contacts":   "contacts",
    "reminders":  "reminders",
    "mail":       "mail",
    "whatsapp":   "whatsapp",
    "signal":     "signal",
    "telegram":   "telegram",
    "vscode":     "vscode_workspaces",
    "health":     "system_health",
  };

  for (const sol of rawTools) {
    let rawName = sol.appKey.toLowerCase();
    let name = rawName;
    
    // Grouping / Deduping
    if (name.includes("_state_vscdb") || name.includes("vscode")) name = "vscode";
    if (name.includes("whatsapp")) name = "whatsapp";
    if (name.includes("chrome") || (sol.appName.toLowerCase().includes("chrome") && name.includes("history"))) name = "chrome";
    if (name.includes("zsh_history") || sol.appName.toLowerCase().includes("shell")) name = "shell";
    if (name.includes(".git") || sol.appName.toLowerCase().includes("git")) name = "git";

    // Clean up names
    name = name.replace(/^static_|^path_|^auto_/, "");
    name = name.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    if (name.startsWith("apple_")) name = name.replace("apple_", "");
    
    // Renaming to requested names
    for (const [key, val] of Object.entries(coreAppsMap)) {
      if (name.includes(key)) {
        name = val;
        break;
      }
    }

    // Strict Noise Filter (Problem 3 & Fix 3)
    const noise = ["tomb", "backup", "cache", "thumbnail", "authorization", "akd", "siri", "heavy_ad", "tipkit", "dock", "vscdb", "metadata", "plist", "json", "coredatabackend", "drivefs", "fsck", "launchd", "shutdown_monitor"];
    
    const isCore = Object.values(coreAppsMap).includes(name) || Object.keys(coreAppsMap).some(k => name.includes(k));
    const isNoise = noise.some(n => name.toLowerCase().includes(n) || sol.appName.toLowerCase().includes(n) || sol.filePath.toLowerCase().includes(n));
    
    // Skip if it is noise AND not a core app
    if (isNoise && !isCore) continue;
    
    // Limit logs to the most important ones (System, Wifi, Install)
    if (name.includes("logs_") && !name.includes("system_log") && !name.includes("wifi_log") && !name.includes("install_log")) continue;

    // Extra strict: if it has "drivefs" anywhere, skip it NO MATTER WHAT (Fix 3)
    if (sol.filePath.toLowerCase().includes("drivefs") || name.includes("drivefs")) continue;

    // Skip generic plists/jsons/low-conf unless core
    if (sol.appKey.startsWith("static_") && (sol.appKey.includes("plist") || sol.appKey.includes("json")) && !isCore) continue;
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

  // Final trim: target 20-22
  finalTools.sort((a,b) => {
    const aCore = Object.values(coreAppsMap).includes(a.name) ? 1 : 0;
    const bCore = Object.values(coreAppsMap).includes(b.name) ? 1 : 0;
    if (aCore !== bCore) return bCore - aCore;
    return b.confidence - a.confidence;
  });

  if (finalTools.length > 22) {
     const coreCount = finalTools.filter(t => Object.values(coreAppsMap).includes(t.name)).length;
     finalTools.splice(Math.max(22, coreCount));
  }

  console.log(JSON.stringify(finalTools));
}

main().catch(() => process.exit(1));
