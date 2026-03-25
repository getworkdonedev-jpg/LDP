import { 
  DelegationContract, NetworkUsage, ContractViolationError 
} from "./types.js";

/**
 * Strict Client-Side Circuit Breaker.
 * Monitors usage in real-time and aborts transport if thresholds are crossed.
 */
export class CircuitBreaker {
  private usage: NetworkUsage = { total_tokens: 0, usd_cost: 0 };

  constructor(
    private readonly contract: DelegationContract,
    private readonly onAbort: (usage: NetworkUsage) => void
  ) {}

  /**
   * Update usage and check against contract.
   * If fail_closed is active and thresholds crossed, trigger abort.
   */
  update(newTokens: number, newCost: number): void {
    this.usage.total_tokens += newTokens;
    this.usage.usd_cost     += newCost;

    if (this.contract.fail_closed) {
      if (this.usage.total_tokens > this.contract.max_tokens || 
          this.usage.usd_cost > this.contract.max_usd) {
        
        this.onAbort(this.usage);
        throw new ContractViolationError(
          { ...this.usage },
          `Budget exceeded: ${this.usage.total_tokens} tokens, $${this.usage.usd_cost.toFixed(4)}`
        );
      }
    }
  }

  getUsage(): NetworkUsage {
    return { ...this.usage };
  }
}
