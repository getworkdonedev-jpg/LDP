# LDP (Local Data Protocol) Server

A powerful local MCP server that allows Cursor (or any MCP client) to query your local data—including messaging history (WhatsApp, Signal, Telegram, Facebook, Instagram), browser history, and more—all without your data ever leaving your machine.

## 🚀 Key Features:
- **Unified Messaging Search**: Query your local message databases for WhatsApp, Signal, Telegram, Facebook Messenger, and Instagram.
- **Privacy-First Decryption**: Handles locally encrypted databases (like Signal and WhatsApp) using on-device security keys.
- **Browser History**: Query recent activity from Chrome, Brave, and Safari.
- **System Insights**: Access shell history, git logs, and local file metadata.
- **Local Data Discovery**: Automatically scans and classifies SQLite databases on your Mac.

## 🛠 Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/getworkdonedev-jpg/LDP.git
   cd LDP
   ```

2. **Install Dependencies**:
   Requires Python 3 and Node.js.
   ```bash
   cd "core-scripts"
   npm install
   ```

3. **Configure Cursor**:
   - Open Cursor Settings (`Cmd + ,`).
   - Go to **Features** → **MCP**.
   - Add a new server:
     - **Name**: `LDP-Local`
     - **Type**: `command`
     - **Command**: `python3 /Users/karthikperumalla/Desktop/LDP/core-scripts/ldp_server.py`

## 🔒 Security
LDP runs entirely on your local machine. It accesses local databases by fetching the necessary security keys from your macOS Keychain or local config files. **Zero bytes of personal data are sent to external servers.**

---
*Created for the Local Data Protocol (LDP) project.*
