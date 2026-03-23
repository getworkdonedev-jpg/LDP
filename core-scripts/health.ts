import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import type { BaseConnector, ConnectorDescriptor, Row, SchemaMap } from "./types.js";

function getCrashLogPath() {
  return path.join(os.homedir(), ".ldp", "crash.log");
}

export function logLDPCrash(errorMsg: string) {
  try {
    const f = getCrashLogPath();
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.appendFileSync(f, `[${new Date().toISOString()}] ${errorMsg}\n`);
  } catch (e) {}
}

export class LDPSystemHealthConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name: "system_health",
    app: "System Health",
    version: "1.0",
    dataPaths: ["/var/log/system.log", "~/Library/Logs/", "~/.ldp/crash.log"],
    permissions: ["system.read"],
    namedQueries: {
      recent_crashes: "What died recently?",
      diagnostics: "Show LDP crash stats",
    },
    description: "System Health — Auto-diagnostic of LDP crashes, OS warnings, and errors.",
  };

  async discover(): Promise<boolean> {
    return true; // Always available
  }

  async schema(): Promise<SchemaMap> {
    return {
      crashes: { timestamp: "Time of error", message: "Error log" }
    };
  }

  async read(query: string, limit = 500): Promise<Row[]> {
    const rows: Row[] = [];
    const crashPath = getCrashLogPath();
    
    // Read local LDP crashes
    if (fs.existsSync(crashPath)) {
      try {
        const text = fs.readFileSync(crashPath, "utf-8");
        const lines = text.split("\n").filter(Boolean);
        for (const line of lines) {
          rows.push({ timestamp: line.substring(1, 25), message: line.substring(27), type: "LDP Crash" });
        }
      } catch (e) {}
    }

    // Heuristically read system.log for broader issues if requested
    if (/system|os|mac|all/i.test(query)) {
      try {
        const out = execSync("tail -n 100 /var/log/system.log 2>/dev/null | grep -i 'error\\|warn\\|crash'", { encoding: "utf-8" });
        const lines = out.split("\n").filter(Boolean);
        for (const line of lines) {
          const parts = line.split(" ");
          rows.push({ timestamp: parts.slice(0, 3).join(" "), message: parts.slice(4).join(" "), type: "System Log" });
        }
      } catch (e) {}
    }

    // Auto-report top errors
    if (rows.length > 0 && query.includes("diagnostics")) {
       rows.unshift({ timestamp: new Date().toISOString(), message: `Last session had ${rows.length} errors`, type: "Summary" });
    }

    return rows.reverse().slice(0, limit);
  }
}
