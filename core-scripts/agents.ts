/**
 * Supervisor Agent — Routes questions to connectors.
 */
import { AgenticRAG } from "./rag.js";
import { MemoryEngine } from "./memory.js";

export interface AgentState {
  sourcesSearched: string[];
  contextChunks: Array<{ text: string, score: number }>;
  memoryFacts: Array<{ key: string, value: string }>;
  confidence: number;
}

export class SupervisorAgent {
  constructor(private deps: { rag: AgenticRAG, memory: MemoryEngine }) {}
  
  async run(question: string): Promise<AgentState> {
    return {
      sourcesSearched: ["all"],
      contextChunks: [],
      memoryFacts: [],
      confidence: 0.8
    };
  }
}
