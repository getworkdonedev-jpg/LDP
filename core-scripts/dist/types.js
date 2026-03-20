/**
 * LDP — Local Data Protocol
 * Core types. Wire format: JSON-RPC 2.0 (same as MCP).
 */
export const LDP_VERSION = "1.0.0";
// ── Message Types ─────────────────────────────────────────────────────────────
export var MsgType;
(function (MsgType) {
    MsgType["HANDSHAKE"] = "HANDSHAKE";
    MsgType["DISCOVER"] = "DISCOVER";
    MsgType["SCHEMA"] = "SCHEMA";
    MsgType["READ"] = "READ";
    MsgType["STREAM"] = "STREAM";
    MsgType["WRITE_INTENT"] = "WRITE_INTENT";
    MsgType["INSIGHT"] = "INSIGHT";
    MsgType["CONTEXT"] = "CONTEXT";
    MsgType["ERROR"] = "ERROR";
    MsgType["ACK"] = "ACK";
})(MsgType || (MsgType = {}));
export var RiskTier;
(function (RiskTier) {
    RiskTier["READ"] = "READ";
    RiskTier["LOW"] = "LOW";
    RiskTier["MEDIUM"] = "MEDIUM";
    RiskTier["HIGH"] = "HIGH";
})(RiskTier || (RiskTier = {}));
export function createMessage(type, payload = {}, opts = {}) {
    return Object.freeze({
        type,
        id: Math.random().toString(36).slice(2, 10),
        timestamp: Date.now() / 1000,
        payload,
        source: opts.source,
        risk: opts.risk ?? RiskTier.READ,
    });
}
export const ackMessage = (payload) => createMessage(MsgType.ACK, payload);
export const errorMessage = (error) => createMessage(MsgType.ERROR, { error });
export const isAck = (msg) => msg.type === MsgType.ACK;
export const isError = (msg) => msg.type === MsgType.ERROR;
