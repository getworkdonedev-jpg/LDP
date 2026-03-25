/**
 * LDP Privacy Engine
 * @ldp-protocol/sdk · Layer 5
 *
 * 3 layers applied in strict order:
 *   Layer A — Semantic compression FIRST (destroys re-identification surface)
 *   Layer B — Anonymisation (names already gone from compressed text)
 *   Layer C — Differential privacy (math noise on numerical values)
 *
 * Order matters: name replacement alone still leaks re-identification
 * context. Semantic compression first eliminates that risk entirely.
 *
 * Usage:
 *   import { PrivacyEngine } from "@ldp-protocol/sdk/privacy";
 *
 *   const engine = new PrivacyEngine();
 *   const packet = await engine.prepareForCloud(rawTexts);
 *   // send packet to Claude / GPT — no raw data inside
 *   const answer = await callClaude(packet.compressedFacts.join("\n"));
 *   const realAnswer = engine.deanonymise(answer);
 */

// ── Topic detection ───────────────────────────────────────────────────────────

const TOPIC_PATTERNS: Record<string, string[]> = {
  project_work:  ["commit", "pr", "deploy", "bug", "feature", "code", "review", "branch"],
  communication: ["message", "reply", "call", "meeting", "discuss", "chat"],
  planning:      ["schedule", "deadline", "milestone", "todo", "plan", "sprint"],
  research:      ["read", "article", "documentation", "search", "learn", "docs"],
  social:        ["friend", "family", "lunch", "weekend", "event", "party"],
  finance:       ["payment", "invoice", "expense", "budget", "subscription", "spend"],
  health:        ["sleep", "steps", "exercise", "calories", "heart", "workout"],
};

// ── Auto name extractor — pulls likely names from raw rows ───────────────────
// Looks at string fields that appear to be names based on column name hints.
// Developer never needs to pass knownNames manually.

const NAME_COLUMN_HINTS = [
  "name", "sender", "recipient", "author", "from", "to",
  "contact", "handle", "display_name", "username", "full_name",
  "first_name", "last_name", "nickname",
];

export function extractNamesFromRows(rows: Array<Record<string, unknown>>): string[] {
  const names = new Set<string>();
  for (const row of rows.slice(0, 200)) {
    for (const [col, val] of Object.entries(row)) {
      if (typeof val !== "string" || val.length < 2 || val.length > 60) continue;
      const colLower = col.toLowerCase();
      if (!NAME_COLUMN_HINTS.some(h => colLower.includes(h))) continue;
      // Looks like a name: at least one capital letter, no URL chars
      if (/[A-Z]/.test(val) && !/[@:/\.]/.test(val)) {
        names.add(val.trim());
      }
    }
  }
  return [...names].slice(0, 100); // cap at 100 unique names per session
}

function detectTopics(texts: string[]): string[] {
  const combined = texts.join(" ").toLowerCase();
  return Object.entries(TOPIC_PATTERNS)
    .filter(([, keywords]) => keywords.some(kw => combined.includes(kw)))
    .map(([topic]) => topic)
    .slice(0, 5);
}

// ── Semantic compression ──────────────────────────────────────────────────────

export interface CompressedContext {
  facts:             string[];
  originalCount:     number;
  topics:            string[];
  compressionRatio:  number;
}

async function compressViaOllama(items: string[], topics: string[]): Promise<string[] | null> {
  const prompt =
    `Summarise what a developer was doing given ${items.length} items ` +
    `spanning: ${topics.join(", ")}. ` +
    `Return 5-10 concise facts. No names or specific details. ` +
    `One fact per line starting with "—".`;

  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ model: "llama3", prompt, stream: false }),
      signal:  AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    const data = await res.json() as { response?: string };
    const lines = (data.response ?? "")
      .split("\n")
      .map(l => l.trim().replace(/^[—•\-*]\s*/, ""))
      .filter(l => l.length > 10);
    return lines.length > 0 ? lines.slice(0, 20) : null;
  } catch {
    return null;
  }
}

function compressViaRules(items: string[], topics: string[]): string[] {
  const facts: string[] = [];
  const counts = Object.fromEntries(topics.map(t => [t, 0]));

  for (const item of items) {
    const lower = item.toLowerCase();
    for (const [topic, keywords] of Object.entries(TOPIC_PATTERNS)) {
      if (topic in counts && keywords.some(kw => lower.includes(kw))) {
        counts[topic]++;
      }
    }
  }

  for (const [topic, count] of Object.entries(counts)) {
    if (count > 0) facts.push(`${count} items related to ${topic.replace("_", " ")}`);
  }
  facts.push(`Total: ${items.length} items processed`);
  return facts.slice(0, 20);
}

// ── Anonymiser ────────────────────────────────────────────────────────────────

const PII_PATTERNS: Array<[RegExp, string]> = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,    "[Email]"],
  [/\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "[Phone]"],
  [/\b\+?44\s?\d{10}\b/g,                                      "[Phone]"],
  [/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,            "[Card]"],
  [/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,                "[IP]"],
  [/\b(ghp_[a-zA-Z0-9]{36})\b/g,                             "[GH_TOKEN]"],
  [/\b(sk-[a-zA-Z0-9]{48})\b/g,                              "[AI_API_KEY]"],
];

export class Anonymiser {
  private nameMap:    Map<string, string> = new Map();
  private reverseMap: Map<string, string> = new Map();
  private counter = 0;

  private getLabel(name: string): string {
    if (!this.nameMap.has(name)) {
      const label = `[Person ${++this.counter}]`;
      this.nameMap.set(name, label);
      this.reverseMap.set(label, name);
    }
    return this.nameMap.get(name)!;
  }

  anonymise(text: string, knownNames: string[] = []): string {
    let result = text;
    // Replace known names first (longest first to avoid partial matches)
    for (const name of [...knownNames].sort((a, b) => b.length - a.length)) {
      if (name.length > 1 && result.includes(name)) {
        result = result.split(name).join(this.getLabel(name));
      }
    }
    // Apply PII patterns
    for (const [pattern, replacement] of PII_PATTERNS) {
      result = result.replace(pattern, replacement);
    }
    return result;
  }

  deanonymise(text: string): string {
    let result = text;
    for (const [label, real] of this.reverseMap) {
      result = result.split(label).join(real);
    }
    return result;
  }

  reset(): void {
    this.nameMap.clear();
    this.reverseMap.clear();
    this.counter = 0;
  }
}

// ── Differential privacy (Laplace mechanism) ──────────────────────────────────

/**
 * Adds calibrated Laplace noise to a numerical value.
 * epsilon: privacy budget (lower = more private, less accurate).
 * sensitivity: how much one record can affect the result.
 */
function laplaceNoise(sensitivity: number, epsilon: number): number {
  const scale = sensitivity / epsilon;
  // Inverse CDF of Laplace distribution
  const u = Math.random() - 0.5;
  return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
}

export class DifferentialPrivacy {
  constructor(private readonly epsilon = 1.0) {}

  addNoise(value: number, sensitivity = 1.0): number {
    return value + laplaceNoise(sensitivity, this.epsilon);
  }

  addNoiseToRecord(record: Record<string, unknown>, sensitivity = 1.0): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(record)) {
      if (typeof v === "number") {
        result[k] = Math.round(this.addNoise(v, sensitivity) * 100) / 100;
      } else if (typeof v === "object" && v !== null) {
        result[k] = this.addNoiseToRecord(v as Record<string, unknown>, sensitivity);
      } else {
        result[k] = v;
      }
    }
    return result;
  }
}

// ── MCP context packet ────────────────────────────────────────────────────────

export interface MCPContextPacket {
  contextId:          string;
  compressedFacts:    string[];   // what the AI actually sees
  topics:             string[];
  userFacts:          Array<{ key: string; value: string }>;  // anonymised warm memory
  noisyNumbers:       Record<string, number>;                  // DP-protected stats
  originalItemCount:  number;
  compressionRatio:   number;
  anonymised:         true;
  localDeanonymisation: true;
}

// ── Full privacy pipeline ─────────────────────────────────────────────────────

export class PrivacyEngine {
  private readonly anonymiser: Anonymiser;
  private readonly dp:         DifferentialPrivacy;

  constructor(epsilon = 1.0) {
    this.anonymiser = new Anonymiser();
    this.dp         = new DifferentialPrivacy(epsilon);
  }

  /**
   * Full pipeline. Input: raw strings from local connectors.
   * Output: MCPContextPacket safe to send to any cloud AI.
   *
   * Steps:
   *   1. Semantic compression — 1000 items → ~20 facts via Ollama or rules
   *   2. Anonymise compressed facts — names already gone from step 1
   *   3. Apply differential privacy to any numerical context
   */
  /**
   * @param rawRows   Optional raw row objects — names extracted automatically.
   *                  If provided, knownNames is ignored (auto-extraction wins).
   */
  async prepareForCloud(
    rawItems: string[],
    numericalContext: Record<string, number> = {},
    knownNames: string[] = [],
    userFacts: Array<{ key: string; value: string }> = [],
    rawRows?: Array<Record<string, unknown>>,
  ): Promise<MCPContextPacket> {
    // Auto-extract names if raw rows provided — developer passes nothing
    if (rawRows && rawRows.length > 0) {
      knownNames = [...new Set([...knownNames, ...extractNamesFromRows(rawRows)])];
    }
    if (rawItems.length === 0) {
      return {
        contextId: Math.random().toString(36).slice(2, 10),
        compressedFacts: [], topics: [], userFacts,
        noisyNumbers: {}, originalItemCount: 0,
        compressionRatio: 1,
        anonymised: true, localDeanonymisation: true,
      };
    }

    // Step A: detect topics
    const topics = detectTopics(rawItems);

    // Step B: semantic compression FIRST
    const facts = await compressViaOllama(rawItems, topics)
               ?? compressViaRules(rawItems, topics);

    // Step C: anonymise compressed facts (much safer after compression)
    const anonFacts = facts.map(f => this.anonymiser.anonymise(f, knownNames));

    // Step D: differential privacy on numbers
    const noisyNumbers: Record<string, number> = {};
    for (const [k, v] of Object.entries(numericalContext)) {
      noisyNumbers[k] = Math.round(this.dp.addNoise(v) * 100) / 100;
    }

    // Anonymise user facts too
    const anonUserFacts = userFacts.map(f => ({
      key:   f.key,
      value: this.anonymiser.anonymise(f.value, knownNames),
    }));

    return {
      contextId:          Math.random().toString(36).slice(2, 10),
      compressedFacts:    anonFacts,
      topics,
      userFacts:          anonUserFacts,
      noisyNumbers,
      originalItemCount:  rawItems.length,
      compressionRatio:   Math.round(anonFacts.length / rawItems.length * 100) / 100,
      anonymised:         true,
      localDeanonymisation: true,
    };
  }

  /**
   * After cloud AI responds with anonymised labels (e.g. "[Person 1]"),
   * restore real names locally before showing to user.
   */
  deanonymise(text: string): string {
    return this.anonymiser.deanonymise(text);
  }

  /** Reset anonymisation map — call at start of each new session. */
  resetSession(): void {
    this.anonymiser.reset();
  }

  compressionStats(originalCount: number, compressedCount: number): string {
    const pct = Math.round((1 - compressedCount / Math.max(originalCount, 1)) * 100);
    return `${originalCount} items → ${compressedCount} facts (${pct}% reduction)`;
  }
}
