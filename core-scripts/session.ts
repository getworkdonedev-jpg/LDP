import { 
  DelegationContract, NetworkUsage, PayloadMode, 
  IdentityCard, ContractViolationError 
} from "./types.js";
import { CircuitBreaker } from "./governance.js";
import { DelegateRouter } from "./router.js";
import { SessionMemoizer } from "./memoizer.js";
import { GovernedObservability } from "./observability.js";
import { Span } from "@opentelemetry/api";

/**
 * GovernedSession — the core of the LDP Governing Model.
 * Orchestrates circuit breaking, routing, and memoization.
 */
export class GovernedSession {
  private readonly breaker: CircuitBreaker;
  private readonly obs = new GovernedObservability();
  private readonly span: Span;

  constructor(
    private readonly sessionId: string,
    private readonly contract: DelegationContract,
    private readonly memoizer: SessionMemoizer,
    private readonly router:   DelegateRouter,
    private readonly onAbort: (usage: NetworkUsage) => void
  ) {
    this.span = this.obs.startSession(sessionId);
    this.breaker = new CircuitBreaker(contract, (usage) => {
      this.obs.logViolation(this.span, { 
        total_tokens: usage.total_tokens, 
        usd_cost:     usage.usd_cost 
      });
      onAbort(usage);
    });
  }

  /**
   * Select the best delegate for a given set of candidates.
   * Enforces Attestation Penalty during selection.
   */
  selectDelegate(candidates: IdentityCard[]): IdentityCard {
    const sorted = this.router.route(candidates);
    const chosen = sorted[0];
    
    this.span.setAttribute("delegate_id", chosen.delegate_id);
    this.span.setAttribute("confidence",  chosen.confidence_score);
    
    return chosen;
  }

  /**
   * Execute a query with progressive fallback and memoization.
   */
  async execute(
    delegate_id: string, 
    initialMode: PayloadMode,
    queryFn: (mode: PayloadMode) => Promise<any>
  ): Promise<any> {
    let mode = initialMode;

    // Check memoizer for bypass
    if (this.memoizer.shouldBypass(delegate_id, mode)) {
      this.obs.logFallback(this.span, mode, PayloadMode.MODE_1, "Memoized failure");
      mode = PayloadMode.MODE_1;
    }

    try {
      const result = await queryFn(mode);
      
      // Monitor usage in real-time
      this.breaker.update(result.tokens || 0, result.cost || 0);
      
      return result;
    } catch (e) {
      if (mode === PayloadMode.MODE_3) {
        this.memoizer.recordFailure(delegate_id, mode);
        this.obs.logFallback(this.span, mode, PayloadMode.MODE_1, String(e));
        return this.execute(delegate_id, PayloadMode.MODE_1, queryFn);
      }
      throw e;
    }
  }

  /**
   * Close the session and flush observability.
   */
  end(): void {
    this.span.end();
  }
}
