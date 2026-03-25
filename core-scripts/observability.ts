import { 
  trace, SpanKind, Span, 
  context, 
} from "@opentelemetry/api";
import { PayloadMode } from "./types.js";

/**
 * Governed Observability.
 * Maps LDP sessions to spans and logs progressive mode fallbacks.
 */
export class GovernedObservability {
  private readonly tracer = trace.getTracer("ldp-governance");

  /**
   * Start a new governed session span.
   */
  startSession(name: string): Span {
    return this.tracer.startSpan(name, {
      kind: SpanKind.SERVER,
    });
  }

  /**
   * Log a progressive payload fallback as a span event.
   */
  logFallback(
    span: Span,
    from_mode: PayloadMode,
    to_mode:   PayloadMode,
    failure_reason: string
  ): void {
    span.addEvent("Progressive Payload Fallback", {
      from_mode,
      to_mode,
      failure_reason,
    });
  }

  /**
   * Log contract violation.
   */
  logViolation(span: Span, details: Record<string, string | number | boolean>): void {
    span.addEvent("Contract Violation", details);
    span.setStatus({ code: 2, message: "Governed session aborted due to contract violation" });
  }
}
