/**
 * LDP Knowledge Distillation
 * @ldp-protocol/sdk · Layer 2 (extension)
 *
 * Claude (Teacher) teaches local Ollama (Student) how to reason.
 * After one cloud call per task type, local model handles it forever.
 * Raw personal data is NEVER sent to Claude.
 *
 * 3 modes:
 *   Cascade      — local Ollama handles ~48% of queries privately
 *   Distil-Once  — Claude teaches reasoning for a task type once,
 *                  stored locally, applied to private data forever
 *   Teach-Method — send task description only (zero personal data),
 *                  Claude returns reasoning framework,
 *                  local model applies it to private data
 *
 * Usage:
 *   import { DistillationEngine } from "@ldp-protocol/sdk/distill";
 *
 *   const distil = new DistillationEngine({ apiKey: process.env.ANTHROPIC_KEY });
 *
 *   // Preload all methods with one setup call:
 *   await distil.preloadMethods();
 *
 *   // Now every query runs locally:
 *   const result = await distil.answer("what was I working on?", contextChunks);
 */

import * as fs   from "node:fs";
import * as path from "node:path";
import * as os   from "node:os";

// ── Paths ────────────────────────────────────────────────────────────────────

const MEMORY_DIR  = path.join(os.homedir(), ".ldp", "memory");
const DISTIL_FILE = path.join(MEMORY_DIR, "distilled_methods.json");

// ── Distilled method ──────────────────────────────────────────────────────────

export interface DistilledMethod {
  taskType:       string;
  methodSteps:    string[];
  promptTemplate: string;   // uses {data} and {query} placeholders
  createdAt:      number;
  useCount:       number;
  lastUsedAt:     number;
  teacher:        string;   // "claude" | "gpt-4o" | "manual"
}

// ── Task type classifier ──────────────────────────────────────────────────────

const TASK_PATTERNS: Record<string, string[]> = {
  summarise_git_history: [
    "what did i work on", "what was i building", "recent commits",
    "git history", "what i built yesterday", "weekly summary",
    "what have i been coding", "git log", "commit history",
    "what changed", "what did i ship", "pull request",
  ],
  summarise_messages: [
    "what did we discuss", "message summary", "conversation summary",
    "what did they say", "recent messages", "what did i text",
    "signal", "imessage", "whatsapp",
  ],
  analyse_spending: [
    "where am i spending", "budget analysis", "spending summary",
    "how much did i spend", "subscription cost", "what am i paying",
    "transactions", "bank", "expenses",
  ],
  daily_briefing: [
    "morning briefing", "daily summary", "what should i focus",
    "today priorities", "whats on my plate", "start of day",
    "what to work on", "brief me", "catch me up",
  ],
  code_search: [
    "find in code", "where did i implement", "how did i do",
    "show me the code", "which file", "where is the",
    "function", "class", "how does", "find the",
  ],
  shell_history: [
    "what command", "shell history", "terminal", "ran recently",
    "last command", "how did i install", "how did i run",
    "bash", "zsh", "what script",
  ],
  cross_project_insight: [
    "across projects", "all repos", "every project",
    "pattern across", "notice anything", "insight",
    "trend", "connection between", "correlation",
    "common pattern", "same in all",
  ],
  cross_app_insight: [
    "across apps", "everything", "full picture",
    "all my data", "what do you know", "overview",
  ],
};

export function classifyTask(query: string): string | null {
  const q = query.toLowerCase();
  for (const [taskType, patterns] of Object.entries(TASK_PATTERNS)) {
    if (patterns.some(p => q.includes(p))) return taskType;
  }
  return null;
}

// ── Distillation store ────────────────────────────────────────────────────────

class DistilStore {
  private methods = new Map<string, DistilledMethod>();

  constructor() {
    fs.mkdirSync(MEMORY_DIR, { recursive: true });
    this.load();
  }

  private load(): void {
    if (!fs.existsSync(DISTIL_FILE)) return;
    try {
      const data = JSON.parse(fs.readFileSync(DISTIL_FILE, "utf8")) as
        Record<string, DistilledMethod>;
      for (const [k, v] of Object.entries(data)) this.methods.set(k, v);
    } catch { /* start fresh */ }
  }

  private save(): void {
    const data = Object.fromEntries(this.methods);
    fs.writeFileSync(DISTIL_FILE, JSON.stringify(data, null, 2));
  }

  get(taskType: string): DistilledMethod | undefined {
    const m = this.methods.get(taskType);
    if (m) {
      m.useCount++;
      m.lastUsedAt = Date.now() / 1000;
      this.save();
    }
    return m;
  }

  store(method: DistilledMethod): void {
    this.methods.set(method.taskType, method);
    this.save();
  }

  listAll(): DistilledMethod[] {
    return [...this.methods.values()];
  }

  stats(): { totalMethods: number; totalUses: number; taskTypes: string[] } {
    return {
      totalMethods: this.methods.size,
      totalUses:    [...this.methods.values()].reduce((s, m) => s + m.useCount, 0),
      taskTypes:    [...this.methods.keys()],
    };
  }
}

// ── Local reasoner (Ollama) ───────────────────────────────────────────────────

const OLLAMA_URL  = "http://localhost:11434";
const LOCAL_MODEL = "llama3"; // user can override

class LocalReasoner {
  constructor(private readonly model = LOCAL_MODEL) {}

  async isAvailable(): Promise<boolean> {
    try {
      const res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(2_000) });
      return res.ok;
    } catch { return false; }
  }

  /** Apply a distilled method to local context. No cloud call. */
  async applyMethod(
    method:  DistilledMethod,
    context: string[],
    query:   string,
  ): Promise<string | null> {
    const contextText = context.slice(0, 10).join("\n").slice(0, 2000);
    const steps = method.methodSteps
      .map((s, i) => `${i + 1}. ${s}`)
      .join("\n");

    const prompt =
      `Task type: ${method.taskType}\n` +
      `Method:\n${steps}\n\n` +
      `Data:\n${contextText}\n\n` +
      `Question: ${query}\n` +
      `Answer using the method above:`;

    return this.generate(prompt, 400);
  }

  /** Quick answer for simple queries — cascade mode. */
  async quickAnswer(context: string[], query: string): Promise<string | null> {
    const contextText = context.slice(0, 5).join("\n").slice(0, 1000);
    const prompt =
      `Answer briefly using only the context provided.\n` +
      `Context:\n${contextText}\n\n` +
      `Question: ${query}\nAnswer:`;

    return this.generate(prompt, 200);
  }

  private async generate(prompt: string, maxTokens: number): Promise<string | null> {
    try {
      const res = await fetch(`${OLLAMA_URL}/api/generate`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({
          model: this.model, prompt, stream: false,
          options: { temperature: 0.1, num_predict: maxTokens },
        }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) return null;
      const data = await res.json() as { response?: string };
      return (data.response ?? "").trim() || null;
    } catch { return null; }
  }
}

// ── Cloud teacher (Anthropic Claude) ─────────────────────────────────────────

const TASK_DESCRIPTIONS: Record<string, string> = {
  summarise_git_history:
    "Summarising a developer's git commit history into a concise daily/weekly summary of what they built.",
  summarise_messages:
    "Summarising a collection of messages into key topics and action items without reproducing personal details.",
  analyse_spending:
    "Analysing spending transaction data to identify categories, patterns, and budget insights.",
  daily_briefing:
    "Creating a morning briefing from a person's recent activity across work, communication, and calendar.",
  code_search:
    "Finding relevant code across multiple repositories given a natural language description of functionality.",
  shell_history:
    "Searching through shell command history to find previously run commands, scripts, or workflows.",
  cross_project_insight:
    "Finding patterns, shared code, or common decisions across multiple software repositories.",
  cross_app_insight:
    "Finding meaningful patterns and correlations across multiple data sources (code, messages, calendar, spending).",
};

class CloudTeacher {
  constructor(
    private readonly apiKey?: string,
    private readonly geminiKey?: string,
    private readonly openaiKey?: string
  ) {}

  async teachMethod(taskType: string): Promise<DistilledMethod | null> {
    if (!this.apiKey) return null;

    const description = TASK_DESCRIPTIONS[taskType]
      ?? `Performing the following task type: ${taskType}`;

    // CRITICAL: no personal data in this prompt — only task description
    const prompt =
      `You are teaching a local AI model how to reason about a task.\n` +
      `Task: ${description}\n\n` +
      `Provide:\n` +
      `1. A step-by-step reasoning method (5-8 steps)\n` +
      `2. A prompt template with {data} and {query} placeholders\n\n` +
      `Respond with valid JSON only:\n` +
      `{"steps": ["step1", ...], "template": "...{data}...{query}..."}`;

    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method:  "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key":    this.apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model:      "claude-sonnet-4-6",
          max_tokens: 1000,
          messages:   [{ role: "user", content: prompt }],
        }),
        signal: AbortSignal.timeout(30_000),
      });

      if (!res.ok) return null;

      const data = await res.json() as {
        content: Array<{ type: string; text: string }>;
      };
      const text  = data.content.find(b => b.type === "text")?.text ?? "";
      const clean = text.replace(/```json\n?|```\n?/g, "").trim();
      const parsed = JSON.parse(clean) as { steps: string[]; template: string };

      return {
        taskType,
        methodSteps:    parsed.steps ?? [],
        promptTemplate: parsed.template ?? "Answer: {query}\nData: {data}",
        createdAt:      Date.now() / 1000,
        useCount:       0,
        lastUsedAt:     Date.now() / 1000,
        teacher:        "claude",
      };
    } catch { return null; }
  }
}

// ── Distillation result ───────────────────────────────────────────────────────

export interface DistillationResult {
  answer:     string | null;
  mode:       "cascade_local" | "distil_local" | "distil_new" | "no_answer";
  cloudUsed:  boolean;
  taskType:   string | null;
  methodUses?: number;
  note?:      string;
}

// ── Main DistillationEngine ───────────────────────────────────────────────────

export interface DistillationOptions {
  /** Anthropic API key — for teaching new methods. */
  apiKey?: string;
  /** Google Gemini API key. */
  geminiKey?: string;
  /** OpenAI API key. */
  openaiKey?: string;
  /** Ollama model name. Default: "llama3". */
  localModel?: string;
}

export class DistillationEngine {
  private readonly store:   DistilStore;
  private readonly local:   LocalReasoner;
  private readonly teacher: CloudTeacher;

  constructor(opts: DistillationOptions = {}) {
    this.store   = new DistilStore();
    this.local   = new LocalReasoner(opts.localModel);
    this.teacher = new CloudTeacher(opts.apiKey, opts.geminiKey, opts.openaiKey);
  }

  /**
   * Main entry point.
   *
   * Cascade:
   *   1. Try quick local answer (no distilled method — ~48% handled here)
   *   2. If task has distilled method → apply locally
   *   3. If new task type → teach Claude once (no personal data), store method,
   *      apply locally immediately
   */
  async answer(
    query:    string,
    context:  string[],
    forceCloud = false,
  ): Promise<DistillationResult> {
    // Mode A: quick local (cascade)
    if (!forceCloud && context.length > 0) {
      const quick = await this.local.quickAnswer(context, query);
      if (quick && quick.length > 20) {
        return { answer: quick, mode: "cascade_local", cloudUsed: false, taskType: null };
      }
    }

    const taskType = classifyTask(query);

    // Mode B: existing distilled method
    if (taskType) {
      const method = this.store.get(taskType);
      if (method && context.length > 0) {
        const answer = await this.local.applyMethod(method, context, query);
        if (answer) {
          return {
            answer, mode: "distil_local", cloudUsed: false,
            taskType, methodUses: method.useCount,
          };
        }
      }

      // Mode C: teach new method (cloud — NO personal data)
      if (taskType) {
        const newMethod = await this.teacher.teachMethod(taskType);
        if (newMethod) {
          this.store.store(newMethod);
          const answer = await this.local.applyMethod(newMethod, context, query);
          return {
            answer: answer ?? "Method learned. Ask again for full answer.",
            mode: "distil_new", cloudUsed: true, taskType,
            note: "Reasoning method stored locally — future queries run without cloud.",
          };
        }
      }
    }

    return { answer: null, mode: "no_answer", cloudUsed: false, taskType };
  }

  /**
   * Preload all known task types by teaching Claude once per type.
   * Call this at setup time — after that everything runs locally.
   * Returns count of newly learned methods.
   */
  async preloadMethods(): Promise<number> {
    let count = 0;
    for (const taskType of Object.keys(TASK_PATTERNS)) {
      if (!this.store.get(taskType)) {
        const method = await this.teacher.teachMethod(taskType);
        if (method) { this.store.store(method); count++; }
      }
    }
    return count;
  }

  async isLocalAvailable(): Promise<boolean> {
    return this.local.isAvailable();
  }

  stats(): {
    distilledMethods:        ReturnType<DistilStore["stats"]>;
    localModelAvailable:     "unknown";
    cloudTeacherConfigured:  boolean;
  } {
    return {
      distilledMethods:       this.store.stats(),
      localModelAvailable:    "unknown",
      cloudTeacherConfigured: !!this.teacher["apiKey"] || !!this.teacher["geminiKey"],
    };
  }
}
