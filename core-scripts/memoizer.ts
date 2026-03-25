import { PayloadMode } from "./types.js";

/**
 * SessionMemoizer to track Payload Mode Fallbacks.
 * Prevents redundant mode negotiation for known delegate failures.
 */
export class SessionMemoizer {
  private readonly failCache = new Map<string, { mode: PayloadMode; expires: number }>();
  private readonly TTL_MS = 30 * 60 * 1000; // 30 minutes

  /**
   * Record a failure for a specific delegate and mode.
   */
  recordFailure(delegate_id: string, mode: PayloadMode): void {
    const key = `${delegate_id}:${mode}`;
    const entry = this.failCache.get(key);
    
    // If it fails twice, cache it for 30 minutes
    if (entry) {
      entry.expires = Date.now() + this.TTL_MS;
    } else {
      this.failCache.set(key, { mode, expires: 0 }); // First fail tracker
    }
  }

  /**
   * Check if a mode should be bypassed for a specific delegate.
   */
  shouldBypass(delegate_id: string, mode: PayloadMode): boolean {
    const key = `${delegate_id}:${mode}`;
    const entry = this.failCache.get(key);
    
    if (entry && entry.expires > Date.now()) {
      return true;
    }
    return false;
  }
}
