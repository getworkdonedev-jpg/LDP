/**
 * LDP — Local Data Protocol
 * Core types. Wire format: JSON-RPC 2.0 (same as MCP).
 */

export const LDP_VERSION = "1.0.0" as const;

// ── Message Types ─────────────────────────────────────────────────────────────

export enum MsgType {
  HANDSHAKE    = "HANDSHAKE",
  DISCOVER     = "DISCOVER",
  SCHEMA       = "SCHEMA",
  READ         = "READ",
  STREAM       = "STREAM",
  WRITE_INTENT = "WRITE_INTENT",
  INSIGHT      = "INSIGHT",
  CONTEXT      = "CONTEXT",
  ERROR        = "ERROR",
  ACK          = "ACK",
}

export enum RiskTier {
  READ   = "READ",    // auto — never needs approval
  LOW    = "LOW",     // auto with 5s cancel window
  MEDIUM = "MEDIUM",  // notification approval
  HIGH   = "HIGH",    // blocking confirmation required
}

export enum PayloadMode {
  MODE_0 = 0, // Raw Text
  MODE_1 = 1, // Structured JSON
  MODE_2 = 2, // Semantic Context
  MODE_3 = 3, // Semantic Graph
}

export interface NetworkUsage {
  total_tokens: number;
  usd_cost:     number;
}

export interface DelegationContract {
  max_tokens:   number;
  max_usd:       number;
  fail_closed:   boolean;
}

export class ContractViolationError extends Error {
  constructor(public readonly usage: NetworkUsage, message: string) {
    super(message);
    this.name = "ContractViolationError";
  }
}

// ── Wire message — JSON-RPC 2.0 compatible ────────────────────────────────────

export interface LDPMessage {
  readonly type:       MsgType;
  readonly id:         string;
  readonly timestamp:  number;
  readonly payload:    Record<string, unknown>;
  readonly source?:    string;
  readonly risk:       RiskTier;
}

export function createMessage(
  type:    MsgType,
  payload: Record<string, unknown> = {},
  opts:    Partial<Pick<LDPMessage, "source" | "risk">> = {}
): LDPMessage {
  return Object.freeze({
    type,
    id:        Math.random().toString(36).slice(2, 10),
    timestamp: Date.now() / 1000,
    payload,
    source:    opts.source,
    risk:      opts.risk ?? RiskTier.READ,
  });
}

export const ackMessage = (
  payload: Record<string, unknown>
): LDPMessage => createMessage(MsgType.ACK, payload);

export const errorMessage = (
  error: string
): LDPMessage => createMessage(MsgType.ERROR, { error });

export const isAck   = (msg: LDPMessage): boolean => msg.type === MsgType.ACK;
export const isError = (msg: LDPMessage): boolean => msg.type === MsgType.ERROR;

// ── Connector types ───────────────────────────────────────────────────────────

export interface ConnectorDescriptor {
  readonly name:         string;
  readonly app:          string;
  readonly version:      string;
  readonly dataPaths:    readonly string[];
  permissions:           readonly string[];
  namedQueries:          Record<string, string>;
  description:           string;
  readonly connectionHints?: Readonly<{
    readonly encryption?: "sqlcipher" | "aes-128-cbc" | "none";
    readonly keychainService?: string;
    readonly keychainAccount?: string;
    readonly pbkdf2Salt?: string;
    readonly pbkdf2Iter?: number;
    readonly ivFormat?: "spaces" | "hex";
  }>;
  readonly identityCard?: IdentityCard;
}

export interface IdentityCard {
  delegate_id:            string;
  confidence_score:       number;
  cryptographic_attestation?: string;
  peer_verification_token?:   string;
  capabilities:           string[];
}

export type SchemaMap = Record<string, Record<string, string>>;

export interface Row {
  [key: string]: unknown;
  _src?:     string;
  _recency?: number;
  _weight?:  number;
}

export interface BaseConnector {
  readonly descriptor: ConnectorDescriptor;
  discover(): Promise<boolean>;
  schema():   Promise<SchemaMap>;
  read(query: string, limit?: number): Promise<Row[]>;
}

// ── Context result ────────────────────────────────────────────────────────────

export interface ContextResult {
  readonly query:      string;
  readonly chunks:     Row[];
  readonly tokensUsed: number;
  readonly sources:    string[];
  readonly totalRows:  number;
  readonly packedRows: number;
}

// ── Consent ───────────────────────────────────────────────────────────────────

export interface ConsentRecord {
  readonly fingerprint: string;
  readonly grantedAt:   number;
  readonly grantedBy:   string;
  readonly app:         string;
  readonly permissions: readonly string[];
}

export interface ConsentRequest {
  readonly connector:   string;
  readonly app:         string;
  readonly permissions: readonly string[];
  readonly dataPaths:   readonly string[];
  readonly description: string;
  readonly fingerprint: string;
  readonly prompt:      string;
}

// ── Engine report ─────────────────────────────────────────────────────────────

export interface EngineReport {
  readonly messages:       number;
  readonly discovers:      number;
  readonly reads:          number;
  readonly cacheHits:      number;
  readonly cacheMisses:    number;
  readonly consentGranted: number;
  readonly consentDenied:  number;
  readonly writeIntents:   number;
  readonly approved:       number;
  readonly rejected:       number;
  readonly errors:         number;
  readonly connected:      readonly string[];
  readonly registered:     readonly string[];
  readonly consented:      readonly string[];
}

// ── Approval callback ─────────────────────────────────────────────────────────

export type ApprovalCallback = (msg: LDPMessage) => Promise<boolean>;

// ── Stream callback ───────────────────────────────────────────────────────────

export type StreamCallback = (event: {
  source:   string;
  newRows:  number;
  total:    number;
}) => Promise<void>;
