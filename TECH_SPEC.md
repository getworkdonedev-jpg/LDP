# LDP Technical Specification (v2.1.0)

**Local Data Platform (LDP)** is a privacy-first, local-native protocol that enables AI agents (like Claude, ChatGPT, or Cursor) to interact with personal data without ever exposing raw PII or sensitive secrets to the cloud.

---

## 1. Core Architecture
LDP is built as a **hybrid-language micro-protocol**:
- **MCP Server (Python)**: The primary interface for AI models, handling security enforcement, PII redaction, and tool execution.
- **Discovery Bridge (Node.js)**: A high-performance scanning engine (`list-tools.ts`) that locates encrypted and standard SQLite databases across macOS (iMessage, Signal, Mail, Chrome, etc.).
- **Dynamic Registry**: Tools are registered live based on user approvals and locally discovered data sources.

---

## 2. The 12-Layer Security Suite
LDP implements a "Personal Data Shield" consisting of 12 distinct security layers:

### Infrastructure Layers
1. **Network Sandbox**: Strict `ImportError` blocks for all networking libraries (requests, socket, urllib) in the tool execution environment.
2. **Local-Only Processing**: All PII detection and resolution happens on-device; no raw data is sent to the LLM.
3. **Approval Manager**: Deny-by-default logic for all data categories (Social, Finance, Work).

### Policy & Protocol Layers
4. **No-Forward Tagging**: Every MCP response includes `[PRIVACY_POLICY]` headers to signal non-leakage requirements to compliant agents.
5. **Session Expiry**: Data tokens are marked with `expires_at: session_end`.
6. **Audit Trail**: Every tool call, agent ID, and argument set is logged locally in `~/.ldp/audit.log`.

### Identity & Data Layers
7. **PII Scrubbing**: Regex-based redaction of Credit Cards, SSNs, and API Keys from all tool outputs.
8. **Name Anonymization**: Automatic reduction of full names to "First Name Only".
9. **Semantic Facts**: Provides compressed, safe context (e.g., "User lives in NYC") instead of raw address data.
10. **Action Tokenization**: Replaces sensitive strings with tokens (e.g., `{{ADDR_HOME}}`) in AI context.
11. **Secure Redirector**: Resolves tokens at the final action endpoint *after* AI generation.
12. **Multi-Agent Identity**: Per-agent permission categories stored in `agent_trust.json`.

---

## 3. Performance & Discovery
- **Instant Startup**: Utilizes `discovery_cache.db` (SQLite) to load tool paths in `<100ms`.
- **Background Scanning**: Discovery scans run in a background thread, syncing new sources without blocking the MCP lifecycle.
- **Dynamic Path Registry**: Maps semantic tool names (`ldp_signal_query`) to transient local paths (including `/private/tmp` copies for locked DBs).

---

## 4. Key MCP Tools
- **`ldp_global_search`**: Cross-platform retrieval using the dynamic path registry.
- **`ldp_get_semantic_facts`**: Secure context layer for user preferences and memberships.
- **`ldp_secure_action`**: Token-aware execution for privacy-safe transactions (ordering food, booking services).
- **`ldp_fused_context`**: Intelligent enrichment (e.g., mapping phone numbers to contact names using local DBs).

---

## 5. Storage & State
- **`~/.ldp/vault.json`**: Encrypted-at-rest (future) storage for raw PII and semantic facts.
- **`~/.ldp/approvals.json`**: Persistence for user consent and category-level permissions.
- **`~/.ldp/discovery_cache.db`**: High-speed index of all local data sources.

---

## 6. Deployment
- **Language**: Python 3.10+ & Node.js 18+.
- **Packaging**: Distributed via `@ldp-protocol/sdk` on npm.
- **Host**: Native support for **Claude Desktop** and **Cursor** via stdio/MCP.
