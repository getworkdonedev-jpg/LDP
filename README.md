# LDP (Local Data Protocol) Server

A powerful local MCP server that allows Cursor (or any MCP client) to query your Signal Desktop messages, Chrome history, shell history, and more — all from your local machine.

## 🚀 Key Features:
- **Signal Decryption**: Decrypts Signal Desktop's SQLite database locally using Chromium `safeStorage` AES decryption.
- **Chrome History**: Query your recent browser activity.
- **Shell History**: Access your recent terminal commands.
- **Git Logs**: Fetch commit history for local repos.
- **Local SQLite Scanner**: Finds all SQLite databases on your Mac.

## 🛠 Setup

1. **Clone the repository**:
   ```bash
   git clone <your-repo-url>
   cd LDP
   ```

2. **Install Dependencies**:
   Requires Python 3 and Node.js.
   ```bash
   # Install Signal's SQLCipher bridge
   cd "core-scripts"
   npm install @signalapp/sqlcipher
   ```

3. **Configure Cursor**:
   - Open Cursor Settings (`Cmd + ,`).
   - Go to **Features** → **MCP**.
   - Add a new server:
     - **Name**: `LDP-Local`
     - **Type**: `command`
     - **Command**: `python3 /Users/karthikperumalla/Desktop/LDP/ldp-server/ldp_server.py`

## 🔒 Security
This server runs entirely locally. It reads your Signal database by fetching the `Signal Safe Storage` key from your macOS Keychain. No data is ever sent to external servers.

---
*Created for the Local Data Protocol (LDP) project.*
