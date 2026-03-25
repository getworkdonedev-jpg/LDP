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
   * First failure: sets a short 60s probe window (we want to retry once).
   * Second failure within that window: escalates to the full 30-minute TTL.
   */
  recordFailure(delegate_id: string, mode: PayloadMode): void {
    const key = `${delegate_id}:${mode}`;
    const entry = this.failCache.get(key);
    const now = Date.now();

    if (entry && entry.expires > now) {
      // Second failure while still in the probe window → full 30-minute ban
      entry.expires = now + this.TTL_MS;
    } else {
      // First failure → short 60s probe window so we retry once before banning
      this.failCache.set(key, { mode, expires: now + 60_000 });
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
