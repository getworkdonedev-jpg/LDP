import { IdentityCard } from "./types.js";

/**
 * DelegateRouter with "Provenance Paradox" Solver.
 * Prioritizes verified identities over high-reporting unverified ones.
 */
export class DelegateRouter {
  
  /**
   * Calculate adjusted score with Attestation Penalty.
   * If confidence > 0.8 but lacks attestation, multiply by 0.5.
   */
  getAdjustedScore(card: IdentityCard): number {
    let score = card.confidence_score;

    const isUnverifiedHighReporting = 
      score > 0.8 && 
      !card.cryptographic_attestation && 
      !card.peer_verification_token;

    if (isUnverifiedHighReporting) {
      score *= 0.5;
    }

    return score;
  }

  /**
   * Sort delegates by adjusted score.
   */
  route(delegates: IdentityCard[]): IdentityCard[] {
    return [...delegates].sort((a, b) => {
      const scoreA = this.getAdjustedScore(a);
      const scoreB = this.getAdjustedScore(b);
      return scoreB - scoreA;
    });
  }
}
