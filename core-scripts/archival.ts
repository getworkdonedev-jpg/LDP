/**
 * Gemini Archival Layer
 * @ldp-protocol/sdk · Layer 2.5
 * 
 * Handles massive 1.5M+ token context windows for long-horizon archival search.
 */
import { LDPEngine } from "./engine.js";

export interface ArchivalResult {
  summary: string;
  timeline: Array<{ date: string, event: string }>;
  confidence: number;
}

export class GeminiArchivalLayer {
  constructor(private readonly geminiKey?: string) {}

  /**
   * Performs a deep archival search across months of data.
   */
  async soulSearch(engine: LDPEngine, query: string, timeRangeDays = 180): Promise<ArchivalResult> {
    if (!this.geminiKey) {
      throw new Error("Gemini API key required for archival soul-search.");
    }

    // 1. Fetch massive data dump from engine
    // We increase the token budget to 1M for archival
    const msg = await engine.query(query, ["*"], { budget: 1_000_000 });
    if (msg.type !== "CONTEXT") return { summary: "No data found.", timeline: [], confidence: 0 };

    // Cap the raw payload sent to Gemini.
    // Gemini 1.5 Pro supports ~1.5M tokens (~6MB of text), but we stay well
    // below that to keep latency and cost sane. 2MB of JSON ≈ ~500K tokens.
    const MAX_PAYLOAD_BYTES = 2 * 1024 * 1024; // 2 MB hard cap
    let rawData = JSON.stringify(msg.payload.chunks);
    if (rawData.length > MAX_PAYLOAD_BYTES) {
      console.warn(`[ARCHIVAL] Payload too large (${(rawData.length / 1024).toFixed(0)} KB) — truncating to ${MAX_PAYLOAD_BYTES / 1024} KB`);
      rawData = rawData.slice(0, MAX_PAYLOAD_BYTES) + "... [TRUNCATED FOR CONTEXT LIMIT]";
    }

    // 2. Call Gemini 1.5 Pro
    const prompt = `
      You are an Archival Intelligence. Analyze the following local raw data from the last ${timeRangeDays} days.
      Query: "${query}"
      
      Tasks:
      1. Provide a semantic summary focusing on patterns and trends.
      2. Construct a chronological timeline of significant events.
      
      Data:
      ${rawData}
      
      Respond in JSON: {"summary": "...", "timeline": [{"date": "...", "event": "..."}]}`;

    try {
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${this.geminiKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { responseMimeType: "application/json" }
        })
      });

      if (!res.ok) throw new Error(`Gemini API Error: ${res.statusText}`);
      const data = await res.json() as any;

      const rawText: string = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) throw new Error("Gemini returned empty candidates");

      // Strip accidental markdown fences before parsing
      const clean = rawText.replace(/```json\n?|```\n?/g, "").trim();
      const result = JSON.parse(clean);

      return {
        summary: result.summary,
        timeline: result.timeline,
        confidence: 0.95
      };
    } catch (e) {
      console.error("Archival Search Failed:", e);
      return { summary: "Archival search failed to process data.", timeline: [], confidence: 0 };
    }
  }
}
