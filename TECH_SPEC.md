# Local Data Protocol (LDP)
## Specification v1.0.0

**Status:** Draft  
**Authors:** LDP Protocol Contributors  
**Repository:** https://github.com/ldp-protocol/spec  
**License:** Apache 2.0  
**Last Updated:** March 2026

---

## Abstract

The Local Data Protocol (LDP) defines a standard interface for AI systems to access personal data stored locally on a user's device — without that data leaving the device, without cloud upload, and without sacrificing the quality of AI responses.

LDP is to personal local data what MCP is to cloud tools: a universal connector layer. Where MCP connects AI to external services, LDP connects AI to the data that already exists on your machine.

---

## 1. Motivation

Every personal AI assistant today faces a fundamental tradeoff: to give useful answers about your life, it needs access to your data. But every existing approach to providing that access either requires uploading data to a server, or produces answers too vague to be useful.

LDP is the third option.

**The problem with existing approaches:**

| Approach | Example | Data leaves device? | Quality |
|---|---|---|---|
| Cloud sync | Notion AI, Gmail AI | Yes — always | High |
| Scraping screenshots | Rewind, Microsoft Recall | No, but stored as screenshots | Medium |
| Manual export | ChatGPT file upload | User does it manually | Low |
| LDP | PACT, any LDP client | **Never** | **High** |

**What LDP enables:**

- "What have I been researching this week?" → reads Chrome history locally
- "Summarise my Signal conversations with Alice" → decrypts Signal DB locally
- "How am I spending money this month?" → reads bank export CSV locally
- "What did I work on in my VS Code projects?" → reads VS Code state DB locally

All of the above: zero bytes of personal data sent to any server.

---

## 2. Core Principles

### 2.1 Local-first

All data read by an LDP connector stays on the device where it was read. The protocol has no concept of remote storage, sync, or upload. Any LDP implementation that transmits raw personal data to a remote server violates this spec.

### 2.2 Consent-required

No connector may read data without explicit prior consent from the user. Consent is:

- **Scoped**: granted per-connector, not system-wide
- **Auditable**: every grant recorded with timestamp, grantedBy, and permissions
- **Revocable**: user may revoke at any time; revocation takes effect immediately
- **Fingerprinted**: consent is tied to a hash of the connector descriptor, so changes to a connector's permissions invalidate existing consent

### 2.3 Encrypted at rest

All LDP state — consent records, schema cache, audit log — is encrypted with AES-256-GCM. The encryption key is derived from a machine-specific identifier via PBKDF2-HMAC-SHA256 (480,000 iterations). Data is never stored in plaintext.

### 2.4 Auditable

Every read, connect, consent grant, and write intent is recorded in a tamper-evident append-only audit log. The log is encrypted but readable by the user at any time. The log stores field names accessed, not values.

### 2.5 Tiered approval for writes

Read operations are auto-approved after consent. Write operations require tiered approval based on risk:

| Tier | Approval | Example |
|---|---|---|
| `READ` | Auto | Reading browsing history |
| `LOW` | Auto with 5s cancel window | Saving a note |
| `MEDIUM` | Notification approval | Editing a calendar event |
| `HIGH` | Blocking confirmation | Sending a message, financial transaction |

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        LDP Client                           │
│         (Claude Desktop, Cursor, PACT, custom app)          │
└────────────────────────┬────────────────────────────────────┘
                         │ JSON-RPC 2.0 (MCP-compatible)
┌────────────────────────▼────────────────────────────────────┐
│                       LDP Engine                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ ConsentStore │  │  SchemaCache │  │    AuditLog      │  │
│  │  (encrypted) │  │  (encrypted) │  │   (encrypted)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                   ContextPacker                      │   │
│  │      relevance scoring · token budgeting             │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ BaseConnector interface
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Chrome     │  │   Signal     │  │  [your app]  │
│  Connector   │  │  Connector   │  │  Connector   │
│              │  │  (SQLCipher) │  │              │
└──────────────┘  └──────────────┘  └──────────────┘
        │                │                │
        ▼                ▼                ▼
   Chrome SQLite   Signal SQLite     any local data
   (plain)         (encrypted)       (any format)
```

### 3.1 Engine

The `LDPEngine` is the central runtime. It:

- Manages the registry of connectors
- Enforces consent before any connector operation
- Packs query results into token-budgeted context windows
- Routes write intents through the approval tier system
- Maintains the encrypted audit log

The engine is stateful but not persistent across process restarts — state is re-loaded from encrypted disk files on startup.

### 3.2 Connectors

A connector is a named implementation of the `BaseConnector` interface that knows how to:

1. **Discover** whether the target app's data exists on this machine
2. **Read the schema** of that data
3. **Query** the data given a natural language question

Connectors are pure data adapters. They contain no AI logic.

### 3.3 Context Packer

The `ContextPacker` takes raw rows from one or more connectors and produces a relevance-ranked, token-budgeted context payload. It scores rows by:

- Keyword overlap with the query (60% weight)
- Recency of the data (30% weight)
- Connector-assigned importance weight (10% weight)

The budget default is 8,000 tokens. Rows are packed in descending score order until the budget is reached.

### 3.4 MCP Adapter

The `MCPAdapter` wraps a running `LDPEngine` and exposes its connected sources as MCP-compatible tool definitions. This means any MCP client — Claude Desktop, Cursor, or any other — can use LDP sources without modification.

---

## 4. Wire Format

LDP uses JSON-RPC 2.0 as its wire format, identical to MCP.

### 4.1 Message structure

```typescript
interface LDPMessage {
  readonly type:       MsgType;     // message type
  readonly id:         string;      // random 8-char ID
  readonly timestamp:  number;      // Unix timestamp (seconds)
  readonly payload:    Record<string, unknown>;
  readonly source?:    string;      // connector name
  readonly risk:       RiskTier;    // READ | LOW | MEDIUM | HIGH
}
```

### 4.2 Message types

| Type | Direction | Description |
|---|---|---|
| `HANDSHAKE` | Engine → Client | Protocol version, capabilities |
| `DISCOVER` | Client → Engine | Check if app data exists |
| `SCHEMA` | Client → Engine | Read data schema |
| `READ` | Client → Engine | Query data |
| `STREAM` | Engine → Client | Streaming read results |
| `WRITE_INTENT` | Client → Engine | Request to write data |
| `CONTEXT` | Engine → Client | Packed context payload |
| `ACK` | Engine → Client | Success acknowledgement |
| `ERROR` | Engine → Client | Error response |

### 4.3 Context payload

The primary response from a query is a `CONTEXT` message:

```typescript
interface ContextResult {
  readonly query:      string;    // original question
  readonly chunks:     Row[];     // relevance-ranked data rows
  readonly tokensUsed: number;    // tokens consumed
  readonly sources:    string[];  // which connectors contributed
  readonly totalRows:  number;    // total rows available
  readonly packedRows: number;    // rows included in this response
}
```

---

## 5. BaseConnector Interface

Every LDP connector implements this interface:

```typescript
interface BaseConnector {
  readonly descriptor: ConnectorDescriptor;
  discover(): Promise<boolean>;
  schema():   Promise<SchemaMap>;
  read(query: string, limit?: number): Promise<Row[]>;
}
```

### 5.1 ConnectorDescriptor

```typescript
interface ConnectorDescriptor {
  readonly name:         string;        // unique identifier, lowercase, no spaces
  readonly app:          string;        // display name of the app
  readonly version:      string;        // connector version
  readonly dataPaths:    string[];      // candidate paths (~ expanded at runtime)
  readonly permissions:  string[];      // e.g. ["history.read", "messages.read"]
  readonly namedQueries: Record<string, string>;  // query key → human description
  readonly description:  string;        // one-sentence description
  readonly connectionHints?: {          // optional — for encrypted sources
    encryption?: "sqlcipher" | "aes-128-cbc" | "none";
    keychainService?: string;
    pbkdf2Salt?: string;
    pbkdf2Iter?: number;
    ivFormat?: "spaces" | "hex";
  };
}
```

### 5.2 Row

```typescript
interface Row {
  [key: string]: unknown;
  _src?:     string;   // set by engine — which connector this came from
  _recency?: number;   // 0-1 score, 1 = most recent
  _weight?:  number;   // 0-1 importance weight, default 1.0
}
```

### 5.3 Minimal connector example

```typescript
import type { BaseConnector, ConnectorDescriptor, Row, SchemaMap } from "@ldp-protocol/sdk";
import { findFirst } from "@ldp-protocol/sdk/connectors";
import Database from "better-sqlite3";

export class ObsidianConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name:         "obsidian",
    app:          "Obsidian",
    version:      "1.0",
    dataPaths:    [
      "~/.config/obsidian/*.sqlite",
      "~/Library/Application Support/obsidian/*.sqlite",
    ],
    permissions:  ["notes.read"],
    namedQueries: {
      recent_notes:   "Notes modified in the last 7 days",
      unlinked_notes: "Notes with no backlinks (orphans)",
      by_tag:         "Notes grouped by tag",
    },
    description: "Obsidian vault — local notes, never uploaded.",
  };

  private dbPath: string | null = null;

  async discover(): Promise<boolean> {
    this.dbPath = findFirst(this.descriptor.dataPaths);
    return this.dbPath !== null;
  }

  async schema(): Promise<SchemaMap> {
    return {
      notes: {
        path:        "vault-relative file path",
        content:     "note body markdown",
        ctime:       "creation time (unix ms)",
        mtime:       "modification time (unix ms)",
        frontmatter: "YAML frontmatter as JSON string",
      },
    };
  }

  async read(query: string, limit = 200): Promise<Row[]> {
    if (!this.dbPath) return [];
    const db = new Database(this.dbPath, { readonly: true });
    const q = query.toLowerCase();
    let sql: string;

    if (/recent|today|week/.test(q)) {
      const since = Date.now() - 7 * 86400 * 1000;
      sql = `SELECT path, mtime FROM files WHERE mtime > ${since} ORDER BY mtime DESC LIMIT ${limit}`;
    } else if (/orphan|unlink/.test(q)) {
      sql = `SELECT path FROM files WHERE path NOT IN (SELECT dest FROM links) LIMIT ${limit}`;
    } else {
      sql = `SELECT path, mtime FROM files ORDER BY mtime DESC LIMIT ${limit}`;
    }

    const rows = db.prepare(sql).all() as Row[];
    db.close();
    const now = Date.now();
    return rows.map(r => ({
      ...r,
      _recency: Math.max(0, 1 - (now - Number(r.mtime)) / (30 * 86400 * 1000)),
    }));
  }
}
```

---

## 6. Consent Model

### 6.1 Consent lifecycle

```
register(connector)
       ↓
requestConsent(name)   ← show prompt to user
       ↓
grantConsent(name)     ← user approves
       ↓
connect(name)          ← discover + schema
       ↓
query(question)        ← read + pack
       ↓
revokeConsent(name)    ← user withdraws (any time)
```

### 6.2 Consent fingerprinting

Consent is tied to a SHA-256 fingerprint of the connector's descriptor object (canonical JSON, keys sorted). If the connector changes its `permissions`, `dataPaths`, `app`, or `name` — the fingerprint changes and consent is invalidated, requiring re-approval.

This prevents a connector from requesting minimal permissions to gain consent, then silently expanding its access.

### 6.3 ConsentRecord

```typescript
interface ConsentRecord {
  readonly fingerprint: string;        // first 16 hex chars of SHA-256
  readonly grantedAt:   number;        // Unix timestamp
  readonly grantedBy:   string;        // "user" | "auto" (testing only)
  readonly app:         string;        // display name at time of grant
  readonly permissions: string[];      // permissions granted
}
```

---

## 7. Encryption Specification

### 7.1 Engine state encryption

All LDP state files use the same scheme:

- **Algorithm:** AES-256-GCM
- **Key derivation:** PBKDF2-HMAC-SHA256, 480,000 iterations
- **Key material:** Machine identifier (platform-specific)
- **Salt:** 32 random bytes, stored in `~/.ldp/.salt` (mode 0600)
- **Nonce:** 12 random bytes, prepended to each ciphertext
- **Auth tag:** 16 bytes, follows nonce
- **Encoding:** Base64

**Wire format:** `[12-byte nonce][16-byte GCM tag][ciphertext]` → Base64

### 7.2 Machine identifier derivation

| Platform | Source |
|---|---|
| macOS | `IOPlatformUUID` from `ioreg` |
| Linux | `/etc/machine-id` |
| Windows | (not yet standardised) |
| Fallback | First non-loopback MAC address |

### 7.3 Connector-level encryption (SQLCipher)

For connectors that access encrypted app databases (Signal, WhatsApp), LDP uses the app's own encryption scheme and key storage — it does not re-encrypt the data. The connector descriptor's `connectionHints` documents the decryption approach.

Signal-specific decryption:

1. Fetch `Signal Safe Storage` password from macOS Keychain
2. Read `encryptedKey` hex string from Signal's `config.json`
3. Strip `v10` prefix (3 bytes)
4. Derive 16-byte AES key: `PBKDF2-HMAC-SHA1(keychainPassword, "saltysalt", 1003 iterations, 16 bytes)`
5. Decrypt with AES-128-CBC, IV = 16 space bytes (0x20)
6. Result is the 64-character hex database key
7. Open DB with `@signalapp/sqlcipher`, apply `PRAGMA key = "x'<key>'"`

**Security requirement:** The decrypted key must be zeroed from memory immediately after the database connection is established.

---

## 8. Privacy Pipeline

When LDP is used with a remote AI (Claude, GPT-4, etc.), raw data must not leave the device. The LDP privacy pipeline transforms data before it reaches any network boundary:

```
raw rows
   ↓
compress        (remove low-signal fields, truncate long values)
   ↓
anonymise       (replace names, emails, phone numbers, URLs with tokens)
   ↓
differential    (add calibrated Laplace noise to numeric fields)
  privacy
   ↓
context packet  (token-budgeted, safe to send to cloud AI)
```

### 8.1 Anonymisation

Names and identifiers are replaced with stable tokens: `Alice → [PERSON_a3f2]`. The token is:

- Stable within a session (same name always maps to same token)
- Not stable across sessions (different salt each time)
- Reversible locally (deanonymise after AI response)

This allows the AI to reason about relationships ("you message [PERSON_a3f2] most often") without seeing actual names.

### 8.2 Differential privacy

Numeric fields (visit counts, message counts, amounts) receive Laplace noise calibrated to sensitivity 1.0, epsilon 1.0. This prevents the AI from inferring exact values while preserving the statistical signal.

---

## 9. MCP Compatibility

LDP is designed to be fully compatible with the Model Context Protocol (MCP). Any MCP client can use LDP sources via the `MCPAdapter` without modification.

### 9.1 Tool mapping

Each connected LDP source becomes one MCP tool:

```
ldp_{connector_name}_query(question: string, limit?: number)
```

If more than one source is connected, a cross-source tool is also registered:

```
ldp_cross_query(question: string, sources?: string)
```

### 9.2 Handshake

```json
{
  "protocolVersion": "2024-11-05",
  "capabilities": { "tools": {} },
  "serverInfo": {
    "name": "ldp-mcp-adapter",
    "version": "1.0.0",
    "description": "LDP (Local Data Protocol) MCP adapter. Privacy-first local data access."
  }
}
```

### 9.3 Tool result format

```json
{
  "sources": ["chrome", "signal"],
  "returned": 47,
  "total": 9235,
  "privacy": "All data read locally — nothing sent to any server",
  "data": [ ...rows ]
}
```

---

## 10. Auto-Discovery

LDP includes an `AutoConnectorGenerator` that scans a machine for unknown SQLite databases and attempts to generate connector descriptors automatically, without requiring manual configuration.

### 10.1 Discovery pipeline

```
scan filesystem for *.db, *.sqlite, *.sqlite3 files
       ↓
match against known app fingerprints (path pattern regex)
       ↓ (if no match)
read SQLite schema (pure Node.js, no native deps)
       ↓
try AI analysis (if API key available)
       ↓ (if no API key or low confidence)
heuristic analysis (column/table name patterns)
       ↓
generate ConnectorDescriptor
       ↓
build live connector
```

### 10.2 Confidence thresholds

| Method | Typical confidence | Threshold to register |
|---|---|---|
| Known fingerprint | 0.95 | 0.90 |
| AI analysis | 0.30–0.95 | 0.60 |
| Heuristic | 0.35–0.75 | 0.35 |

Results below threshold are discarded. Results are deduplicated by app name — one connector per app.

### 10.3 Skip patterns

The scanner skips directories matching: `node_modules`, `.git`, `Caches`, `Cache`, `GPUCache`, `Code Cache`, `ShaderCache`, `Logs`, `tmp`, `temp`, `.Trash`, and other system/cache paths.

---

## 11. Security Requirements

This section documents REQUIRED security properties for any compliant LDP implementation.

### 11.1 Process isolation

The LDP engine process must not share memory with untrusted processes. On macOS, it must not hold FDA (Full Disk Access) permissions beyond the minimum required for the currently active connectors.

### 11.2 Key lifetime

Decrypted encryption keys (e.g. Signal's 64-char hex key) must be:
- Never written to disk in plaintext
- Never included in log output
- Never sent over any network interface
- Zeroed from memory as soon as the database connection is open

### 11.3 Network binding

The MCP adapter must bind exclusively to `127.0.0.1`. It must not bind to `0.0.0.0` or any external interface. Each session must require a fresh authentication token.

### 11.4 State file permissions

All files in `~/.ldp/` must be created with mode `0600` (user read/write only). The directory must be created with mode `0700`.

### 11.5 Connector sandboxing

Each connector's `read()` call should execute with the minimum required filesystem permissions. A connector that reads `~/Library/Application Support/Signal/` must not also be able to read `~/Documents/`.

---

## 12. Audit Log Format

The audit log stores events without storing the values accessed. Each entry:

```typescript
interface AuditEntry {
  ts:         number;   // Unix timestamp
  event:      string;   // CONNECT | READ | CONSENT_GRANTED | CONSENT_REVOKED | WRITE_INTENT | ...
  connector:  string;   // connector name
  risk:       RiskTier;
  query?:     string;   // first 80 chars of query (no data values)
  rows?:      number;   // count of rows returned
  action?:    string;   // for write intents
  grantedBy?: string;   // for consent events
}
```

The log is append-only, capped at 10,000 entries (oldest dropped). It is encrypted with the same scheme as all other LDP state.

---

## 13. Known App Catalogue

The following apps have verified connector implementations or fingerprint entries in the reference implementation:

| App | Category | Encryption | Platform |
|---|---|---|---|
| Google Chrome | browser | none (SQLite) | macOS, Linux, Windows |
| Chromium | browser | none (SQLite) | macOS, Linux |
| Brave Browser | browser | none (SQLite) | macOS |
| Firefox | browser | none (SQLite) | macOS, Linux, Windows |
| Signal Desktop | messaging | SQLCipher (Chromium SafeStorage) | macOS |
| WhatsApp Desktop | messaging | none (SQLite) | macOS |
| iMessage | messaging | none (SQLite) | macOS |
| Telegram Desktop | messaging | SQLite | macOS, Linux |
| VS Code | developer | none (SQLite) | macOS, Linux, Windows |
| Cursor | developer | none (SQLite) | macOS |
| Obsidian | notes | none (SQLite) | macOS, Linux, Windows |
| Apple Notes | notes | none (SQLite) | macOS |
| Apple Health | health | SQLite (FDA required) | macOS |
| Spotify | media | none (SQLite) | macOS, Linux, Windows |
| Apple Contacts | contacts | none (SQLite) | macOS |

---

## 14. Versioning

LDP follows semantic versioning. Breaking changes to:

- `BaseConnector` interface → major version bump
- `ConnectorDescriptor` shape → major version bump
- `LDPMessage` wire format → major version bump
- `ConsentRecord` shape → major version bump
- `ContextResult` shape → minor version bump
- New message types → minor version bump
- Bug fixes and clarifications → patch version bump

The current spec is v1.0.0. All implementations must declare the spec version they conform to.

---

## 15. Governance

The LDP specification is maintained by the LDP Protocol Contributors at https://github.com/ldp-protocol/spec.

Changes are proposed via GitHub Issues and accepted via Pull Request with review from at least two maintainers. Security-relevant changes require 72-hour minimum review period.

The reference implementation is `@ldp-protocol/sdk` published to npm under Apache 2.0. The specification itself is licensed Apache 2.0.

---

## Appendix A — RiskTier definitions

| Value | Meaning | Approval required |
|---|---|---|
| `READ` | Passive data read | Never — auto-approved after consent |
| `LOW` | Minor write with easy undo | Auto with 5-second cancellation window |
| `MEDIUM` | Significant write, hard to undo | User notification, tap to approve |
| `HIGH` | Irreversible or high-stakes action | Blocking confirmation dialog |

---

## Appendix B — Permission string conventions

Permissions follow the format `{resource}.{action}`:

```
history.read          browsing history
messages.read         message content
messages.write        sending messages
contacts.read         contact names, numbers, emails
calendar.read         events and appointments
calendar.write        creating/modifying events
health.read           health and fitness data
finance.read          transactions, balances
notes.read            note content
notes.write           creating/modifying notes
files.read            document content
workspace.read        editor state, recent files
extensions.read       installed extensions
playback.read         media listening history
```

---

## Appendix C — Changelog

**v1.0.0** (March 2026)
- Initial specification
- BaseConnector interface
- Consent model
- Encryption specification
- MCP compatibility layer
- Auto-discovery pipeline
- Privacy pipeline
- Security requirements
- Known app catalogue

---

*LDP — Local Data Protocol. Use MCP for cloud tools. Use LDP for local data.*
