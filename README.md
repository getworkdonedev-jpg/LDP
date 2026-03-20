# 🛡️ LDP: Local Data Protocol

A high-performance, zero-config MCP server that transforms your local application data (Signal, iMessage, Notes, Mail, Chrome) into a searchable knowledge base for Cursor and other AI assistants.

## 🌟 Why LDP?
Unlike other connectors, LDP features a **Dynamic Discovery Engine** that automatically finger prints local SQLite databases and identifies them—no manual path configuration required.

### 🚀 Key Features:
- **Universal Search**: Query iMessage, Apple Notes, and local Gmail (via Apple Mail) with optimized "Smart Queries".
- **Signal Decryption**: Native decryption of Signal Desktop messages using macOS Keychain.
- **Zero-Config**: Just start the server; it finds your data automatically.
- **Browser Insights**: Deep indexing of Chrome, Brave, and Firefox history.
- **Developer Pulse**: Access shell history, recent VS Code/Cursor files, and git logs.

---

## 🛠 Setup

### 1. Install Dependencies
Requires **Python 3.10+** and **Node.js 18+**.

```bash
# Clone the repo
git clone https://github.com/yourusername/LDP.git
cd LDP

# Install the Signal bridge (required for Signal decryption)
cd core-scripts
npm install
```

### 2. Configure Your AI (e.g., Cursor)
1. Open **Cursor Settings** (`Cmd + ,`) > **Features** > **MCP**.
2. Add a new server:
   - **Name**: `LDP-Local`
   - **Type**: `command`
   - **Command**: `python3 /FULL/PATH/TO/LDP/signal-mcp/ldp_server.py`

### 🔒 Privacy First
LDP is **100% local**. It reads your data from your disk using temporary snapshots. It never sends your messages or history to the cloud.

---
*Built for the future of local-first AI agentic workflows.*
