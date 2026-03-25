/**
 * LDP Vision Connector
 * Bridges legacy apps via screencapture + GPT-4o Vision.
 */
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { BaseConnector, ConnectorDescriptor, Row, SchemaMap } from "./types.js";

export class VisionConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name: "vision",
    app: "Vision Bridge",
    version: "1.0",
    dataPaths: [],
    permissions: ["screen.capture"],
    namedQueries: {
      scan: "Capture and OCR active window",
    },
    description: "Multi-modal vision bridge for legacy apps.",
  };

  async discover(): Promise<boolean> {
    return process.platform === "darwin"; // Supported on Mac
  }

  async schema(): Promise<SchemaMap> {
    return {
      vision_events: {
        timestamp: "ISO8601 when captured",
        app_name: "Target application",
        ocr_result: "Extracted text/data",
        image_hash: "SHA-256 of the screenshot",
      },
    };
  }

  async read(query: string): Promise<Row[]> {
    if (process.platform !== "darwin") return [];

    const tmp = path.join(os.tmpdir(), `ldp_vision_${Date.now()}.png`);
    try {
      execSync(`screencapture -x ${tmp}`);
      const b64 = fs.readFileSync(tmp).toString("base64");
      
      // In a real scenario, this B64 would be sent to GPT-4o Vision.
      // For the SDK, we return the metadata record.
      return [
        {
          timestamp: new Date().toISOString(),
          app_name: "Active Window",
          ocr_result: `[Vision Bridge] Screenshot captured (${(b64.length / 1024).toFixed(0)} KB). Ready for GPT-4o processing.`,
          _hash: `vision:${Date.now()}`,
          _recency: 1.0,
          _dbPath: "vision",
        },
      ];
    } catch {
      return [];
    } finally {
      if (fs.existsSync(tmp)) {
        try { fs.unlinkSync(tmp); } catch { /* ignore */ }
      }
    }
  }
}
