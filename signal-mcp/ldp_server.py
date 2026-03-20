"""
LDP MCP Server — connects to Cursor via native MCP support.
Pure Python, zero dependencies beyond stdlib.
Reads: Chrome history, shell history, VS Code recent files,
       git log, terminal commands, any SQLite on your Mac.
"""

import sqlite3, shutil, os, json, sys, tempfile, subprocess
from pathlib import Path
from datetime import datetime, timezone

# ── Common Paths & Global State ───────────────────────────────────
HOME = Path.home()
SIGNAL_CONFIG = HOME / "Library/Application Support/Signal/config.json"
SIGNAL_DB = HOME / "Library/Application Support/Signal/sql/db.sqlite"
CORE_SCRIPTS = HOME / "Desktop/LDP/core-scripts"

DISCOVERED_APPS = {} # AppName -> ConnectionHint/Descriptor

SOURCES = {
    "chrome": HOME / "Library/Application Support/Google/Chrome/Default/History",
    "brave":  HOME / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
    "firefox": HOME / "Library/Application Support/Firefox/Profiles",
    "vscode": HOME / "Library/Application Support/Code/User/globalStorage/state.vscdb",
    "cursor": HOME / "Library/Application Support/Cursor/User/globalStorage/state.vscdb",
    "imessage": HOME / "Library/Messages/chat.db",
    "notes": HOME / "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
}

def find_mail_db() -> Path:
    mail_dir = HOME / "Library/Mail"
    if not mail_dir.exists(): return Path("")
    v_dirs = sorted(list(mail_dir.glob("V*")), reverse=True)
    for v in v_dirs:
        db = v / "MailData/Envelope Index"
        if db.exists(): return db
    return Path("")

# ── SQLite reader (lock-safe copy) ────────────────────────────────
def read_sqlite(path: Path, query: str) -> list[dict]:
    if not path.exists():
        return [{"error": f"Path not found: {path}"}]
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        shutil.copy2(path, tmp.name)
        con = sqlite3.connect(tmp.name)
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute(query).fetchall()]
        con.close()
        return rows
    except PermissionError:
        return [{"error": f"LDP Permission Denied: Mac Full Disk Access required for {path.name}. Grant FDA to 'Terminal' and 'Cursor' in System Settings."}]
    except Exception as e:
        return [{"error": str(e)}]
    finally:
        try: os.unlink(tmp.name)
        except: pass
    return []

# ── Tool implementations ──────────────────────────────────────────

def tool_chrome_history(limit: int = 30) -> str:
    path = SOURCES["chrome"] if SOURCES["chrome"].exists() else SOURCES["brave"]
    rows = read_sqlite(path, f"SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT {limit}")
    if not rows or (isinstance(rows, list) and len(rows) > 0 and "error" in rows[0]):
        return "Chrome/Brave history not found or error reading."
    out = [f"{'URL':<60} {'VISITS':>6}"]
    for r in rows:
        url = str(r.get("url",""))[:58]
        out.append(f"{url:<60} {r.get('visit_count',0):>6}")
    return "\n".join(out)

def tool_shell_history(limit: int = 50) -> str:
    hists = [HOME / ".zsh_history", HOME / ".bash_history"]
    for h in hists:
        if h.exists():
            try:
                lines = h.read_text(errors="ignore").splitlines()
                cmds = [l.split(";")[-1] if ";" in l else l for l in lines if l.strip()]
                return "\n".join(cmds[-limit:][::-1])
            except: continue
    return "No shell history found."

def tool_discover_apps() -> str:
    """Run the TypeScript auto-connector to find and identify local databases."""
    try:
        result = subprocess.run(
            ["npx", "tsx", str(CORE_SCRIPTS / "auto-connector.ts"), "--json"],
            capture_output=True, text=True, timeout=30, cwd=str(CORE_SCRIPTS)
        )
        if result.returncode != 0: return f"Discovery failed: {result.stderr}"
        apps = json.loads(result.stdout)
        if not apps: return "No apps found."
        
        out = ["Discovered apps:\n"]
        for a in apps:
            name = a.get("descriptor", {}).get("app", "Unknown")
            DISCOVERED_APPS[name.lower()] = a
            out.append(f"  - {name} ({a.get('sourcePath','')})")
        return "\n".join(out)
    except Exception as e: return f"Error: {e}"

def tool_query_app(app_name: str, query: str = "", limit: int = 10) -> str:
    """Dynamically query a discovered app. Handles decryption automatically."""
    name_low = app_name.lower()
    
    # 1. Check hardcoded fallbacks first (Faster!)
    path = None
    if "imessage" in name_low: path = SOURCES["imessage"]
    elif "notes" in name_low: path = SOURCES["notes"]
    elif "chrome" in name_low: path = SOURCES["chrome"]
    elif "brave" in name_low: path = SOURCES["brave"]
    elif "mail" in name_low or "gmail" in name_low: path = find_mail_db()
    
    # 2. If not a fallback, check dynamic discovery
    if not path or not path.exists():
        if name_low not in DISCOVERED_APPS: tool_discover_apps()
        if name_low in DISCOVERED_APPS:
            path = Path(DISCOVERED_APPS[name_low]["sourcePath"])
    
    if not path or not path.exists():
        if "signal" in name_low: return tool_signal_messages(limit=limit)
        return f"App '{app_name}' not found locally. To read Gmail, ensure you have synced your account in the Mac Mail app."

    # 3. Handle Encryption
    if "signal" in name_low:
        return tool_signal_messages(limit=limit)
    
    # 4. Smart Query Logic: Provide sensible defaults for known apps
    actual_query = query
    if not actual_query:
        if "imessage" in name_low:
            actual_query = f"SELECT text, datetime(date/1000000000 + 978307200,'unixepoch','localtime') as date FROM message WHERE text IS NOT NULL ORDER BY date DESC LIMIT {limit}"
        elif "notes" in name_low:
            actual_query = f"SELECT ZTITLE as title FROM ZICCLOUDSYNCINGOBJECT WHERE ZTITLE IS NOT NULL LIMIT {limit}"
        elif "mail" in name_low or "gmail" in name_low:
            # Join messages with addresses to get sender info
            actual_query = f"SELECT m.subject, a.address as sender FROM messages m JOIN addresses a ON m.sender = a.ROWID ORDER BY m.date_received DESC LIMIT {limit}"
        else:
            actual_query = "SELECT * FROM sqlite_master LIMIT 1"

    data = read_sqlite(path, actual_query)
    return json.dumps(data, indent=2)

def tool_installed_apps(include_system: bool = False) -> str:
    paths = [Path("/Applications"), Path.home() / "Applications"]
    if include_system: paths.append(Path("/System/Applications"))
    apps = []
    for p in paths:
        if p.exists():
            apps.extend([item.stem for item in p.iterdir() if item.suffix == ".app"])
    return "Installed Apps:\n" + "\n".join(sorted(list(set(apps))))

def tool_diagnostics() -> str:
    """Check server health and capabilities."""
    return json.dumps({
        "status": "ready",
        "version": "1.1.0-Dynamic-Discovery",
        "paths": {
            "server": str(Path(__file__)),
            "core": str(CORE_SCRIPTS)
        },
        "discovered_apps_count": len(DISCOVERED_APPS),
        "capabilities": ["Signal-SQLCipher", "iMessage-SmartQuery", "AppleNotes-Heuristic", "AppleMail-GmailProxy", "Dynamic-AutoConnect"]
    }, indent=2)

def tool_signal_messages(limit: int = 10, query_type: str = "messages") -> str:
    """Decrypt and read Signal messages."""
    try:
        # 1. Get Key from Keychain
        res = subprocess.run(["security", "find-generic-password", "-s", "Signal Safe Storage", "-w"], capture_output=True, text=True)
        keychain_pass = res.stdout.strip()
        
        # 2. Decrypt Signal Key from config
        config = json.loads(SIGNAL_CONFIG.read_text())
        enc_key = config["encryptedKey"]
        
        # We'll use the Node tool for the heavy lifting of SQLCipher
        sql = "SELECT body, sent_at FROM messages ORDER BY sent_at DESC LIMIT " + str(limit)
        if query_type == "conversations":
            sql = "SELECT name FROM conversations WHERE name IS NOT NULL LIMIT " + str(limit)

        node_code = f"""
const {{ Database }} = require('{CORE_SCRIPTS}/node_modules/@signalapp/sqlcipher');
const crypto = require('crypto');
const fs = require('fs');

// Decrypt the key v10
const keychainPass = '{keychain_pass}';
const encKey = '{enc_key}';
const salt = Buffer.from('saltysalt');
const iterations = 1003;
const derivedKey = crypto.pbkdf2Sync(keychainPass, salt, iterations, 16, 'sha1');
const ciphertext = Buffer.from(encKey, 'hex').slice(3);
const iv = Buffer.from(' '.repeat(16));
const decipher = crypto.createDecipheriv('aes-128-cbc', derivedKey, iv);
let decrypted = decipher.update(ciphertext);
decrypted = Buffer.concat([decrypted, decipher.final()]);
const dbKey = decrypted.toString().trim();

const tmp = '/tmp/sig.' + Date.now() + '.db';
fs.copyFileSync('{SIGNAL_DB}', tmp);
const db = new Database(tmp);
db.pragma(`key = "x'${{dbKey}}'"`);
console.log(JSON.stringify(db.prepare("{sql}").all()));
db.close();
fs.unlinkSync(tmp);
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cjs', delete=False) as f:
            f.write(node_code)
            tmp_path = f.name
        
        res = subprocess.run(["node", tmp_path], capture_output=True, text=True)
        os.unlink(tmp_path)
        return res.stdout if res.returncode == 0 else f"Error: {res.stderr}"
    except Exception as e: return f"Error: {e}"

# ── MCP Protocol ──────────────────────────────────────────────────

TOOLS = [
    {"name": "ldp_diagnostics", "description": "Check LDP server status and version.", "inputSchema": {"type":"object"}},
    {"name": "ldp_query_app", "description": "Query any discovered app (Signal, Chrome etc)", "inputSchema": {"type":"object", "properties": {"app_name": {"type":"string"}, "query":{"type":"string"}}}},
    {"name": "ldp_discover_apps", "description": "Scan Mac for local data apps", "inputSchema": {"type":"object"}},
    {"name": "ldp_installed_apps", "description": "List all apps in /Applications", "inputSchema": {"type":"object"}},
    {"name": "ldp_signal_messages", "description": "Read Signal messages", "inputSchema": {"type":"object", "properties": {"limit":{"type":"integer"}}}},
    {"name": "ldp_chrome_history", "description": "Read Chrome history", "inputSchema": {"type":"object"}},
    {"name": "ldp_shell_history", "description": "Read shell history", "inputSchema": {"type":"object"}},
]

TOOL_MAP = {
    "ldp_diagnostics": lambda a: tool_diagnostics(),
    "ldp_query_app": lambda a: tool_query_app(a.get("app_name",""), a.get("query","")),
    "ldp_discover_apps": lambda a: tool_discover_apps(),
    "ldp_installed_apps": lambda a: tool_installed_apps(),
    "ldp_signal_messages": lambda a: tool_signal_messages(a.get("limit",10)),
    "ldp_chrome_history": lambda a: tool_chrome_history(),
    "ldp_shell_history": lambda a: tool_shell_history(),
}

def main():
    sys.stderr.write("[LDP] Dynamic Server Started\n")
    for line in sys.stdin:
        try:
            req = json.loads(line)
            rid = req.get("id")
            if req.get("method") == "initialize":
                json.dump({"jsonrpc":"2.0", "id":rid, "result": {"protocolVersion":"2024-11-05", "capabilities":{"tools":{}}, "serverInfo":{"name":"ldp","version":"1.0"}}}, sys.stdout)
            elif req.get("method") == "tools/list":
                json.dump({"jsonrpc":"2.0", "id":rid, "result": {"tools": TOOLS}}, sys.stdout)
            elif req.get("method") == "tools/call":
                name = req["params"]["name"]
                args = req["params"].get("arguments", {})
                try:
                    res = TOOL_MAP[name](args)
                    json.dump({"jsonrpc":"2.0", "id":rid, "result": {"content": [{"type":"text", "text": str(res)}]}}, sys.stdout)
                except Exception as e:
                    json.dump({"jsonrpc":"2.0", "id":rid, "result": {"content": [{"type":"text", "text": f"Error: {e}"}], "isError": True}}, sys.stdout)
            sys.stdout.write("\n"); sys.stdout.flush()
        except: pass

if __name__ == "__main__": main()
