import * as path from "path";
import fetch from "node-fetch";

export async function askProvider({baseUrl, model, apiKey, schema}: any) {
  const response = await fetch(baseUrl + "/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + apiKey
    },
    body: JSON.stringify({
      model,
      max_tokens: 300,
      messages: [{
        role: "user",
        content: `Identify this SQLite database.
Tables: ${Object.keys(schema.schemaContext || {}).join(", ")}
Sample columns: ${Object.values(schema.schemaContext || {}).flat().slice(0,10).join(", ")}
Row counts: ${JSON.stringify(schema.counts || {})}

Reply in JSON only:
{
  "appName": "exact app name",
  "confidence": 0.0,
  "category": "communication",
  "safeToRead": true,
  "description": "what this stores"
}`
      }]
    })
  });
  if (!response.ok) throw new Error("API error: " + response.status);
  const data = await (response.json() as Promise<any>);
  const text = data.choices[0].message.content;
  const match = text.match(/\{[\s\S]*\}/);
  return JSON.parse(match ? match[0] : text);
}

export async function askGemini({model, apiKey, schema}: any) {
  const prompt = `Identify this SQLite database.
Tables: ${Object.keys(schema.schemaContext || {}).join(", ")}
Sample columns: ${Object.values(schema.schemaContext || {}).flat().slice(0,10).join(", ")}
Row counts: ${JSON.stringify(schema.counts || {})}

Reply in JSON only:
{
  "appName": "exact app name",
  "confidence": 0.0,
  "category": "communication",
  "safeToRead": true,
  "description": "info"
}`;
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: "application/json" }
    })
  });
  if (!response.ok) throw new Error("API error: " + response.status);
  const data = await (response.json() as Promise<any>);
  return JSON.parse(data.candidates[0].content.parts[0].text);
}

export async function isOllamaRunning() {
  try {
    const res = await fetch("http://localhost:11434/api/tags");
    return res.ok;
  } catch { return false; }
}

export async function identifyWithTeachers(schemaContext: any, counts: any, filePath: string) {
  const schema = { schemaContext, counts };

  // Level 1: Groq
  if (process.env.GROQ_API_KEY) {
    try {
      console.log("[TEACHER] Asking Groq...");
      const result = await askProvider({
        baseUrl: "https://api.groq.com/openai/v1",
        model: "llama3-70b-8192",
        apiKey: process.env.GROQ_API_KEY,
        schema
      });
      if (result.confidence > 0.7) return { ...result, source: "groq" };
    } catch (e) { console.log("[TEACHER] Groq failed", e); }
  }

  // Level 2: Gemini
  if (process.env.GEMINI_API_KEY) {
    try {
      console.log("[TEACHER] Asking Gemini...");
      const result = await askGemini({
        model: "gemini-1.5-flash",
        apiKey: process.env.GEMINI_API_KEY,
        schema
      });
      if (result.confidence > 0.7) return { ...result, source: "gemini" };
    } catch (e) { console.log("[TEACHER] Gemini failed", e); }
  }

  // Level 3: Ollama
  if (await isOllamaRunning()) {
    try {
      console.log("[TEACHER] Asking local Ollama...");
      const result = await askProvider({
        baseUrl: "http://localhost:11434/v1",
        model: "llama3.1",
        apiKey: "ollama",
        schema
      });
      if (result.confidence > 0.6) return { ...result, source: "ollama" };
    } catch (e) { console.log("[TEACHER] Ollama failed", e); }
  }

  // Level 4: Claude
  if (process.env.ANTHROPIC_API_KEY) {
    try {
      console.log("[TEACHER] Asking Claude...");
      const { identifyWithClaude } = await import("./brain.js");
      const result = await identifyWithClaude(schemaContext, counts, process.env.ANTHROPIC_API_KEY);
      if (result && result.confidence > 0.4) return { ...result, source: "claude" };
    } catch (e) { console.log("[TEACHER] Claude failed", e); }
  }

  return {
    appName: "unknown_" + path.basename(filePath).replace(/[^a-zA-Z0-9]/g, "_"),
    confidence: 0,
    needsRecheck: true,
    source: "none"
  };
}
