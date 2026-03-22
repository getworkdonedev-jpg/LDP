"""
LDP MCP Server — connects to Cursor via native MCP support.
Pure Python, zero dependencies beyond stdlib.
Reads: Chrome history, shell history, VS Code recent files,
       git log, terminal commands, any SQLite on your Mac.
"""

import sqlite3, shutil, os, json, sys, tempfile, subprocess, platform
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Union, Dict, Any

# ── Common Paths & Global State ───────────────────────────────────
HOME = Path.home()
SCRIPT_DIR = Path(__file__).parent
# CORE_SCRIPTS is either alongside the server or in the parent directory
CORE_SCRIPTS = SCRIPT_DIR / "../core-scripts"
if not CORE_SCRIPTS.exists():
    CORE_SCRIPTS = SCRIPT_DIR / "core-scripts"

DISCOVERED_APPS = {} # AppName -> ConnectionHint/Descriptor

# Platform Detection
PLATFORM = platform.system().lower() # 'darwin', 'linux', 'windows'

SIGNAL_CONFIG = HOME / "Library/Application Support/Signal/config.json"
SIGNAL_DB = HOME / "Library/Application Support/Signal/sql/db.sqlite"
if PLATFORM == "windows":
    SIGNAL_CONFIG = Path(os.getenv("APPDATA", "")) / "Signal/config.json"
    SIGNAL_DB = Path(os.getenv("APPDATA", "")) / "Signal/sql/db.sqlite"

def get_platform_paths():
    """Returns platform-specific base paths for common apps."""
    if PLATFORM == "darwin":
        return {
            "chrome": HOME / "Library/Application Support/Google/Chrome",
            "brave": HOME / "Library/Application Support/BraveSoftware/Brave-Browser",
            "edge": HOME / "Library/Application Support/Microsoft Edge",
            "vscode": HOME / "Library/Application Support/Code/User/globalStorage/state.vscdb",
            "cursor": HOME / "Library/Application Support/Cursor/User/globalStorage/state.vscdb",
            "imessage": HOME / "Library/Messages/chat.db",
            "notes": HOME / "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
            "mail": HOME / "Library/Mail",
        }
    elif PLATFORM == "windows":
        appdata = Path(os.getenv("APPDATA", ""))
        localapp = Path(os.getenv("LOCALAPPDATA", ""))
        return {
            "chrome": localapp / "Google/Chrome/User Data",
            "brave": localapp / "BraveSoftware/Brave-Browser/User Data",
            "edge": localapp / "Microsoft/Edge/User Data",
            "vscode": appdata / "Code/User/globalStorage/state.vscdb",
            "cursor": appdata / "Cursor/User/globalStorage/state.vscdb",
        }
    else: # Linux/Other
        config = Path(os.getenv("XDG_CONFIG_HOME", HOME / ".config"))
        return {
            "chrome": config / "google-chrome",
            "brave": config / "BraveSoftware/Brave-Browser",
            "edge": config / "microsoft-edge",
            "vscode": config / "Code/User/globalStorage/state.vscdb",
            "cursor": config / "Cursor/User/globalStorage/state.vscdb",
        }

PLATFORM_PATHS = get_platform_paths()

def find_browser_history(browser: str) -> list[Path]:
    """Finds all browser history paths across all profiles."""
    if browser not in PLATFORM_PATHS: return []
    base = PLATFORM_PATHS[browser]
    if not base.exists(): return []
    
    found = []
    # Profiles are usually subdirs. Look for 'History' file in them.
    # On Windows/Linux, profiles are often in 'User Data' or similar.
    search_dirs = [base]
    if PLATFORM != "darwin": # Windows/Linux often have profiles directly in base or 'User Data'
        search_dirs.append(base)
    
    # Common profile names to check first (fast)
    for profile in ["Default", "Profile 1", "Profile 2", "Guest"]:
        path = base / profile / "History"
        if path.exists(): found.append(path)
    
    # Then glob for others
    for p in base.glob("Profile *"):
        path = p / "History"
        if path.exists() and path not in found:
            found.append(path)
            
    return found

def find_mail_db() -> Optional[Path]:
    mail_dir = PLATFORM_PATHS.get("mail")
    if mail_dir is None: return None
    if not isinstance(mail_dir, Path) or not mail_dir.exists(): return None
    try:
        v_dirs = sorted(list(mail_dir.glob("V*")), reverse=True)
        for v in v_dirs:
            db = v / "MailData/Envelope Index"
            if db.exists(): return db
    except: pass
    return None

# ── Active Sources ────────────────────────────────────────────────
SOURCES = {
    "chrome": find_browser_history("chrome"),
    "brave":  find_browser_history("brave"),
    "edge":   find_browser_history("edge"),
    "vscode": PLATFORM_PATHS.get("vscode", Path("")),
    "cursor": PLATFORM_PATHS.get("cursor", Path("")),
    "imessage": PLATFORM_PATHS.get("imessage", Path("")),
    "notes": PLATFORM_PATHS.get("notes", Path("")),
}

# ── SQLite reader (lock-safe copy) ────────────────────────────────
def read_sqlite(path: Path, query: str) -> List[Dict[str, Any]]:
    """Returns a list of rows (dicts)."""
    if not path or not path.exists():
        return []
    
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
        sys.stderr.write(f"Permission Denied: {path}\n")
        return []
    except Exception as e:
        sys.stderr.write(f"SQLite Error: {e}\n")
        return []
    finally:
        try: os.unlink(tmp.name)
        except: pass
    
    return []

# ── Tool implementations ──────────────────────────────────────────

def tool_chrome_history(limit: int = 30) -> str:
    # Ensure all components are lists before adding
    c = SOURCES.get("chrome", [])
    b = SOURCES.get("brave", [])
    e = SOURCES.get("edge", [])
    paths = (c if isinstance(c, list) else [c]) + \
            (b if isinstance(b, list) else [b]) + \
            (e if isinstance(e, list) else [e])
    actual_paths = [p for p in paths if isinstance(p, Path) and p.exists()]
    if not actual_paths:
        return "No browser history found (Chrome/Brave/Edge)."
    
    all_rows: List[Dict] = []
    for path in actual_paths:
        try:
            rows_data = read_sqlite(path, f"SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT {limit}")
            all_rows.extend(rows_data)
        except: continue
    
    if not all_rows:
        return "No history entries found."
        
    # Sort and limit combined results
    all_rows.sort(key=lambda x: x.get("visit_count", 0), reverse=True)
    rows: List[Dict] = []
    for i in range(min(len(all_rows), limit)):
        r = all_rows[i]
        if isinstance(r, dict):
            rows.append(r)
    
    out = [f"{'URL':<60} {'VISITS':>6}"]
    for r in rows:
        url_str = str(r.get("url", ""))
        url_cut = url_str[0:58] # type: ignore
        visits  = int(r.get("visit_count", 0))
        out.append(f"{url_cut:<60} {visits:>6}") # type: ignore
    return "\n".join(out)

def tool_shell_history(limit: int = 50) -> str:
    hists = [HOME / ".zsh_history", HOME / ".bash_history"]
    for h in hists:
        if h.exists():
            try:
                lines = h.read_text(errors="ignore").splitlines()
                cmds = [l.split(";")[-1] if ";" in l else l for l in lines if l.strip()]
                # Return unique commands, reversed (most recent first)
                out = []
                seen = set()
                for cmd in reversed(cmds):
                    if cmd not in seen:
                        out.append(cmd)
                        seen.add(cmd)
                        if len(out) >= limit: break
                return "\n".join(out)
            except: continue
    return "No shell history found."

def tool_discover_apps(at_startup: bool = False) -> str:
    """Run the TypeScript auto-connector to find and identify local databases."""
    try:
        # Use run-auto.ts for the latest v2.0 logic, but fallback to auto-connector if needed
        script = CORE_SCRIPTS / "auto-connector.ts"
        if not script.exists():
            return "Discovery failed: TypeScript source not found."
            
        result = subprocess.run(
            ["npx", "tsx", str(script), "--json"],
            capture_output=True, text=True, timeout=60, cwd=str(CORE_SCRIPTS)
        )
        if result.returncode != 0:
            return f"Discovery failed: {result.stderr}"
        
        # Parse JSON output
        try:
            apps = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Discovery failed: Invalid JSON output from scanner."

        if not apps:
            return "No new apps found."
        
        count = 0
        for a in apps:
            if not isinstance(a, dict): continue
            desc = a.get("descriptor", {})
            if not isinstance(desc, dict): continue
            
            name = str(desc.get("app", "Unknown"))
            name_key = str(desc.get("name", name.lower().replace(" ", "_")))
            
            # CRITICAL: Do not add Signal as a default tool (user approval required)
            if "signal" in name_key.lower() and at_startup:
                DISCOVERED_APPS[name_key.lower()] = a
                continue

            # Register app in global state
            DISCOVERED_APPS[name_key.lower()] = a
            
            # Dynamically add to TOOLS if not already present
            tool_name = f"ldp_{name_key.lower()}_query"
            if not any(t["name"] == tool_name for t in TOOLS):
                TOOLS.append({ # type: ignore
                    "name": tool_name,
                    "description": f"Query {name} data. {desc.get('description', '')}",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Optional SQL query. Leave empty for smart defaults."},
                            "limit": {"type": "integer", "default": 10}
                        }
                    }
                })
                # Use a closure helper to capture name_key correctly
                def create_handler(nk):
                    return lambda args: tool_query_app(nk, args.get("query", ""), args.get("limit", 10))
                TOOL_MAP[tool_name] = create_handler(name_key) # type: ignore
                count = count + 1
        
        if at_startup:
            return f"Synchronized {count} apps."
        return f"Discovered {count} new apps and registered them as tools."
    except Exception as e:
        return f"Error during discovery: {e}"

def tool_query_app(app_name: str, query: str = "", limit: int = 10) -> str:
    """Dynamically query a discovered app. Handles decryption automatically."""
    name_low = app_name.lower()
    
    # 1. Check hardcoded fallbacks first (Faster!)
    path = None
    if "imessage" in name_low: 
        p = SOURCES.get("imessage")
        path = p if isinstance(p, Path) else None
    elif "notes" in name_low:
        p = SOURCES.get("notes")
        path = p if isinstance(p, Path) else None
    elif "chrome" in name_low: 
        c = SOURCES.get("chrome", [])
        if isinstance(c, list) and len(c) > 0: path = c[0]
    elif "brave" in name_low: 
        b = SOURCES.get("brave", [])
        if isinstance(b, list) and len(b) > 0: path = b[0]
    elif "edge" in name_low: 
        e = SOURCES.get("edge", [])
        if isinstance(e, list) and len(e) > 0: path = e[0]
    elif "mail" in name_low or "gmail" in name_low: path = find_mail_db()
    
    # 2. If not a fallback, check dynamic discovery
    if path is None or not path.exists():
        if name_low not in DISCOVERED_APPS: tool_discover_apps()
        if name_low in DISCOVERED_APPS:
            app_data = DISCOVERED_APPS[name_low]
            if isinstance(app_data, dict):
                p_str = str(app_data.get("sourcePath", ""))
                path = Path(p_str)
    
    if path is None or not path.exists():
        if "signal" in name_low: return tool_signal_messages(limit=limit)
        return f"App '{app_name}' not found locally."

    # 3. Handle Encryption
    if "signal" in name_low:
        return tool_signal_messages(limit=limit)
    
    # 4. Smart Query Logic: Provide sensible defaults for known apps
    actual_query = query
    if not actual_query:
        if "imessage" in name_low:
            # Join message with handle to get sender ID
            actual_query = f"""
                SELECT 
                    m.text, 
                    h.id as sender,
                    datetime(m.date/1000000000 + 978307200,'unixepoch','localtime') as date 
                FROM message m 
                LEFT JOIN handle h ON m.handle_id = h.ROWID 
                WHERE m.text IS NOT NULL 
                ORDER BY m.date DESC LIMIT {limit}
            """
        elif "notes" in name_low:
            # Get note title and some snippet
            actual_query = f"SELECT ZTITLE as title, ZSNIPPET as snippet FROM ZICCLOUDSYNCINGOBJECT WHERE ZTITLE IS NOT NULL LIMIT {limit}"
        elif "mail" in name_low or "gmail" in name_low:
            # Join messages with addresses to get sender info
            actual_query = f"""
                SELECT 
                    m.subject, 
                    a.address as sender,
                    datetime(m.date_received + 978307200, 'unixepoch', 'localtime') as date
                FROM messages m 
                JOIN addresses a ON m.sender = a.ROWID 
                ORDER BY m.date_received DESC LIMIT {limit}
            """
        else:
            actual_query = "SELECT * FROM sqlite_master LIMIT 1"

    try:
        if path is None or not isinstance(path, Path):
             return f"Error: App '{app_name}' path not found or invalid."
        data = read_sqlite(path, actual_query)
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error querying {app_name}: {e}"

def tool_installed_apps(include_system: bool = False) -> str:
    paths = [Path("/Applications"), Path.home() / "Applications"]
    if include_system: paths.append(Path("/System/Applications"))
    apps = []
    for p in paths:
        if p.exists():
            apps.extend([item.stem for item in p.iterdir() if item.suffix == ".app"])
    return "Installed Apps:\n" + "\n".join(sorted(list(set(apps))))

def tool_check_permissions() -> str:
    """Check read access to protected paths and provide FDA guidance."""
    results = {}
    chrome_src = SOURCES.get("chrome", [])
    chrome_path = None
    if isinstance(chrome_src, list) and len(chrome_src) > 0:
        chrome_path = chrome_src[0]
    elif isinstance(chrome_src, Path):
        chrome_path = chrome_src

    protected = {
        "iMessage": PLATFORM_PATHS.get("imessage"),
        "Apple Mail": find_mail_db(),
        "Apple Notes": PLATFORM_PATHS.get("notes"),
        "Chrome History": chrome_path,
    }
    for name, p in protected.items():
        if p is None:
            results[name] = "Not Found"
            continue
        try:
            # Ensure p is a Path object for open()
            target = Path(str(p))
            with open(target, 'rb') as f:
                f.read(1)
            results[name] = "Access Granted"
        except PermissionError:
            results[name] = "Permission Denied (FDA required)"
        except Exception as e:
            results[name] = f"Error: {e}"
            
    status = json.dumps(results, indent=2)
    guidance = "\n\nTo fix 'Permission Denied', grant 'Full Disk Access' to 'Terminal' and 'Cursor' in System Settings > Privacy & Security."
    return status + guidance

def tool_global_search(query: str, limit: int = 5) -> str:
    """Search across all major connected sources."""
    results = []
    # Search Shell
    shell = tool_shell_history(limit=50)
    for line in shell.splitlines():
        if query.lower() in line.lower():
            results.append({"source": "shell", "content": line})
            if len(results) >= limit: break
            
    # Search Browser
    c = SOURCES.get("chrome", [])
    b = SOURCES.get("brave", [])
    e = SOURCES.get("edge", [])
    paths = (list(c) if isinstance(c, list) else [c]) + \
            (list(b) if isinstance(b, list) else [b]) + \
            (list(e) if isinstance(e, list) else [e])
    for p_raw in paths:
        if not p_raw: continue
        p = Path(str(p_raw)) if not isinstance(p_raw, Path) else p_raw
        if not p.exists(): continue
        if len(results) >= limit * 2: break
        try:
            query_safe = str(query).replace("'", "''")
            rows = read_sqlite(p, f"SELECT title, url FROM urls WHERE title LIKE '%{query_safe}%' OR url LIKE '%{query_safe}%' LIMIT {limit}")
            for r in rows:
                if isinstance(r, dict):
                    results.append({"source": "browser", "content": f"{str(r.get('title'))} ({str(r.get('url'))})"})
        except: continue
    
    final_res = []
    for i in range(min(len(results), limit * 2)):
        r_item = results[i]
        final_res.append(r_item)
    return json.dumps(final_res, indent=2)

def tool_diagnostics() -> str:
    """Check server health and capabilities."""
    return json.dumps({
        "status": "ready",
        "platform": PLATFORM,
        "version": "1.2.0-CrossPlatform",
        "paths": {
            "server": str(Path(__file__)),
            "core": str(CORE_SCRIPTS)
        },
        "discovered_apps_count": len(DISCOVERED_APPS),
        "capabilities": ["Signal-SQLCipher", "iMessage-SmartQuery", "AppleNotes-Heuristic", "AppleMail-GmailProxy", "Dynamic-AutoConnect", "Global-Search", "FDA-Diagnostics"]
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

        sql_safe = json.dumps(sql)
        node_code = f"""
const {{ Database }} = require('{CORE_SCRIPTS}/node_modules/@signalapp/sqlcipher');
const crypto = require('crypto');
const fs = require('fs');

// Decrypt the key v10
const keychainPass = {json.dumps(keychain_pass)};
const encKey = {json.dumps(enc_key)};
const salt = Buffer.from('saltysalt'); // Note: Signal salt is traditionally 'saltysalt' for v10
const iterations = 1003;              // Note: Signal iterations is traditionally 1003 for v10
const derivedKey = crypto.pbkdf2Sync(keychainPass, salt, iterations, 16, 'sha1');
const ciphertext = Buffer.from(encKey, 'hex').slice(3);
const iv = Buffer.from(' '.repeat(16)); // Note: Signal IV is traditionally 16 spaces for v10
const decipher = crypto.createDecipheriv('aes-128-cbc', derivedKey, iv);
let decrypted = decipher.update(ciphertext);
decrypted = Buffer.concat([decrypted, decipher.final()]);
const dbKey = decrypted.toString().trim();

const tmp = '/tmp/sig.' + Date.now() + '.db';
fs.copyFileSync('{SIGNAL_DB}', tmp);
const db = new Database(tmp);
db.pragma(`key = "x'${{dbKey}}'"`);
console.log(JSON.stringify(db.prepare({sql_safe}).all()));
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
    {"name": "ldp_check_permissions", "description": "Check Mac Full Disk Access permissions.", "inputSchema": {"type":"object"}},
    {"name": "ldp_global_search", "description": "Search across all local history/data.", "inputSchema": {"type":"object", "properties": {"query": {"type":"string"}}}},
    {"name": "ldp_query_app", "description": "Query any discovered app (Signal, Chrome etc)", "inputSchema": {"type":"object", "properties": {"app_name": {"type":"string"}, "query":{"type":"string"}}}},
    {"name": "ldp_discover_apps", "description": "Scan Mac for local data apps", "inputSchema": {"type":"object"}},
    {"name": "ldp_installed_apps", "description": "List all apps in /Applications", "inputSchema": {"type":"object"}},
    {"name": "ldp_chrome_history", "description": "Read browser history", "inputSchema": {"type":"object"}},
    {"name": "ldp_shell_history", "description": "Read shell history", "inputSchema": {"type":"object"}},
]

TOOL_MAP = {
    "ldp_diagnostics": lambda a: tool_diagnostics(),
    "ldp_check_permissions": lambda a: tool_check_permissions(),
    "ldp_global_search": lambda a: tool_global_search(a.get("query","")),
    "ldp_query_app": lambda a: tool_query_app(a.get("app_name",""), a.get("query","")),
    "ldp_discover_apps": lambda a: tool_discover_apps(),
    "ldp_installed_apps": lambda a: tool_installed_apps(),
    "ldp_chrome_history": lambda a: tool_chrome_history(),
    "ldp_shell_history": lambda a: tool_shell_history(),
}

def main():
    sys.stderr.write("[LDP] Dynamic Server Starting...\n")
    
    # Run discovery at startup to populate TOOLS
    tool_discover_apps(at_startup=True)
    
    sys.stderr.write("[LDP] Dynamic Server Ready\n")
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
