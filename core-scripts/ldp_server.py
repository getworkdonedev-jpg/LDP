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

# ── Approval Management ──────────────────────────────────────────

CATEGORY_MAP = {
    "browser":       ["chrome", "brave", "firefox", "safari", "edge", "arc"],
    "communication": ["signal", "whatsapp", "imessage", "telegram", "messages"],
    "work":          ["slack", "zoom", "vscode", "cursor", "git", "jira", "linear", "teams", "webex", "pycharm"],
    "personal":      ["claude", "spotify", "notes", "calendar", "animoji", "photos"],
    "system":        ["shell", "dock", "system", "kernel", "drivefs", "tipkit", "coredatabackend"],
}

def classify_app(name_key: str) -> str:
    """Map a normalized app name key to a category."""
    for cat, keywords in CATEGORY_MAP.items():
        if any(kw in name_key for kw in keywords):
            return cat
    return "unknown"

class ApprovalManager:
    def __init__(self):
        self.approvals_file = HOME / ".ldp" / "approvals.json"
        self.state = {}
        self.load()

    def load(self):
        if self.approvals_file.exists():
            try:
                with open(self.approvals_file, "r") as f:
                    self.state = json.load(f)
            except:
                self.state = {}

    def save(self):
        self.approvals_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.approvals_file, "w") as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            sys.stderr.write(f"[LDP] Error saving approvals: {e}\n")

    def is_approved(self, category: str) -> bool:
        return self.state.get(category) == "approved"

    def is_denied(self, category: str) -> bool:
        return self.state.get(category) == "denied"

    def has_asked(self, category: str) -> bool:
        return category in self.state

    def request(self, category: str, auto_save: bool = True) -> str:
        """Prompt user via macOS dialog and store result."""
        # Only works on macOS for now
        if PLATFORM != "darwin":
            self.state[category] = "approved"
            if auto_save: self.save()
            return "approved"

        cat_names = {
            "browser": "Browser Data (Chrome, Safari, Edge)",
            "communication": "Communication (Signal, WhatsApp, iMessage)",
            "work": "Work Tools (Zoom, Slack, VS Code)",
            "personal": "Personal (Claude, Notes, Spotify)",
            "system": "System (Shell, Dock, OS cache)",
        }
        friendly_name = cat_names.get(category, f"'{category}' apps")

        apple_script = f'''
        display dialog "LDP wants to access your local {friendly_name}. Allow access?" ¬
        buttons {{"Deny", "Allow"}} default button "Allow" with title "LDP Connector" with icon caution
        '''
        
        try:
            res = subprocess.run(["osascript", "-e", apple_script], capture_output=True, text=True)
            if "Allow" in res.stdout:
                status = "approved"
            else:
                status = "denied"
        except:
            status = "denied"  # fail closed

        self.state[category] = status
        if auto_save:
            self.save()
        return status

    def run_first_run_approvals(self):
        """Check all standard categories and prompt for any that are missing."""
        changed = False
        for cat in CATEGORY_MAP.keys():
            if not self.has_asked(cat):
                self.request(cat, auto_save=False)
                changed = True
        if changed:
            self.save()

approvals = ApprovalManager()

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

def tool_claude_history(limit: int = 20, query: str = "") -> str:
    """Read Claude Desktop local session history and MCP config."""
    claude_dir = HOME / "Library" / "Application Support" / "Claude"
    if not claude_dir.exists():
        return "Claude Desktop not found on this machine."
    
    results: List[Dict] = []
    
    # 1. Read agent-mode session files
    session_glob = str(claude_dir / "local-agent-mode-sessions" / "*" / "*" / ".claude.json")
    import glob
    session_files = sorted(glob.glob(session_glob))
    
    for sf in session_files:
        try:
            p = Path(sf)
            with open(sf) as f:
                data = json.load(f)
            # Extract meaningful session metadata
            session_id = p.parent.name
            workspace_id = p.parent.parent.name
            mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat()
            first_start = data.get("firstStartTime", "unknown")
            entry = {
                "type": "claude_session",
                "session_id": session_id,
                "workspace_id": workspace_id,
                "first_start": first_start,
                "last_modified": mtime,
                "keys": list(data.keys()),
            }
            results.append(entry)
        except: continue
    
    # 2. Read MCP config
    config_path = claude_dir / "claude_desktop_config.json"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
            mcp_servers = config.get("mcpServers", {})
            results.append({
                "type": "mcp_config",
                "server_count": len(mcp_servers),
                "servers": list(mcp_servers.keys()),
                "full_config": config,
            })
        except: pass
    
    # 3. Read window state
    ws = claude_dir / "window-state.json"
    if ws.exists():
        try:
            with open(ws) as f:
                wdata = json.load(f)
            results.append({"type": "window_state", **wdata})
        except: pass
    
    # Filter by query if provided
    if query:
        q = query.lower()
        results = [r for r in results if any(q in str(v).lower() for v in r.values())]
    
    if not results:
        return "No Claude session data found."
    
    # Apply limit
    limited = results[:limit]
    
    out = [f"Claude Desktop Data ({len(results)} items found, showing {len(limited)}):\n"]
    for r in limited:
        rtype = r.get("type", "unknown")
        if rtype == "claude_session":
            out.append(f"  📝 Session {r['session_id'][:16]}...")
            out.append(f"     Workspace: {r['workspace_id'][:16]}...")
            out.append(f"     Started: {r['first_start']}")
            out.append(f"     Modified: {r['last_modified']}")
        elif rtype == "mcp_config":
            out.append(f"  ⚙️  MCP Config: {r['server_count']} servers registered")
            for s in r["servers"]:
                out.append(f"       - {s}")
        elif rtype == "window_state":
            out.append(f"  🪟 Window: {r}")
        out.append("")
    
    return "\n".join(out)

def tool_request_approvals() -> str:
    """Manually trigger approval requests for any unapproved categories."""
    count_before = len(TOOLS)
    for cat in CATEGORY_MAP.keys():
        if not approvals.is_approved(cat):
            approvals.request(cat)
    # Re-run discovery to pick up newly approved apps
    tool_discover_apps()
    count_after = len(TOOLS)
    return f"Approval flow complete. {count_after - count_before} new tools registered."

def count_db_rows(db_path: Path) -> int:
    """Count total rows across all tables in a SQLite db using a temp copy."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    total = 0
    try:
        shutil.copy2(str(db_path), tmp.name)
        con = sqlite3.connect(tmp.name)
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for tbl in tables:
            try:
                row = con.execute(f"SELECT count(*) FROM \"{tbl}\"").fetchone()
                if row: total += row[0]
            except: pass
        con.close()
    except: pass
    finally:
        try: os.unlink(tmp.name)
        except: pass
    return total

def max_table_rows(db_path: Path) -> tuple:
    """Return (max_rows, table_count) from the db (temp-copy safe)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    max_rows = 0
    table_count = 0
    try:
        shutil.copy2(str(db_path), tmp.name)
        con = sqlite3.connect(tmp.name)
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        table_count = len(tables)
        for tbl in tables:
            try:
                row = con.execute(f"SELECT count(*) FROM \"{tbl}\"").fetchone()
                if row and row[0] > max_rows: max_rows = row[0]
            except: pass
        con.close()
    except: pass
    finally:
        try: os.unlink(tmp.name)
        except: pass
    return (max_rows, table_count)

# Paths/patterns to skip during full walk
WALK_SKIP_PATTERNS = [
    "Cache", "cache", ".enc", "StoreKit", "root_preference_sqlite",
    "WebKit", "GPUCache", "ShaderCache", "blob_storage", "IndexedDB",
    "Service Worker", "Code Cache", "first_party_sets",
    "com.apple.ProtectedCloudStorage", "com.apple.akd",
    "networkserviceproxy", "videosubscriptionsd", "RemoteManagement",
    ".macromedia", "Cookies",
]

def tool_discover_apps(at_startup: bool = False) -> str:
    """Walk ALL of ~/Library/Application Support for .sqlite/.db files and register
    any database with at least one table having more than 10 rows as an LDP tool."""
    search_root = HOME / "Library" / "Application Support"
    extensions = {".sqlite", ".db"}
    
    # Signal is known but requires consent — never auto-register
    CONSENT_REQUIRED = {"signal", "whatsapp", "telegram"}

    found_paths: List[Path] = []
    try:
        for dirpath, dirnames, filenames in os.walk(str(search_root)):
            # Prune skip dirs in-place so os.walk doesn't descend into them
            dirnames[:] = [d for d in dirnames if not any(s.lower() in d.lower() for s in WALK_SKIP_PATTERNS)]
            for fname in filenames:
                if any(s.lower() in fname.lower() for s in WALK_SKIP_PATTERNS):
                    continue
                if Path(fname).suffix.lower() in extensions:
                    found_paths.append(Path(dirpath) / fname)
    except Exception as e:
        sys.stderr.write(f"[LDP] Walk error: {e}\n")

    count = 0
    skipped_consent = 0
    low_density = 0
    results = []

    for db_path in found_paths:
        # Derive a friendly name — walk up the path for a meaningful folder name
        parts = list(db_path.parts)
        # Start from parent, skip generic folders and numeric IDs
        GENERIC = {"databases", "sql", "data", "db", "appdata", "storage", "plugin_config", "partitions", "webex", "plugins"}
        app_name = None
        for part in reversed(parts[:-1]):  # skip the file itself
            if part.lower() in GENERIC: continue
            if part.isnumeric() or (len(part) > 20 and part.replace("-", "").isalnum()): continue
            if part.lower().startswith("profile ") or part.lower() in ("default", "guest profile", "system profile"): continue
            if part.lower() in ("library", "application support", "users"): break
            app_name = part
            break
        if not app_name:
            # Last resort: use db filename without extension
            app_name = db_path.stem
        name_key = app_name.lower().replace(" ", "_").replace(".", "_").replace("-", "_")
        tool_name = f"ldp_{name_key}_query"

        # Skip apps requiring consent (Signal etc)
        if any(c in name_key for c in CONSENT_REQUIRED):
            skipped_consent += 1
            DISCOVERED_APPS[name_key] = {"sourcePath": str(db_path), "requiresConsent": True}
            continue

        # Density check — skip if max rows <= 10 AND fewer than 5 tables
        try:
            peak, table_count = max_table_rows(db_path)
        except:
            peak, table_count = 0, 0

        if peak <= 10 and table_count < 5:
            low_density += 1
            continue

        # Check category approval
        category = classify_app(name_key)
        if approvals.is_denied(category):
            skipped_consent += 1
            continue
        if not approvals.has_asked(category):
            if approvals.request(category) == "denied":
                skipped_consent += 1
                continue

        # Register app
        DISCOVERED_APPS[name_key] = {"sourcePath": str(db_path), "peak_rows": peak}

        if not any(t["name"] == tool_name for t in TOOLS): # type: ignore
            TOOLS.append({ # type: ignore
                "name": tool_name,
                "description": f"Query {app_name} local database ({db_path.name}, {peak} max rows in a table)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Optional SQL query. Leave empty for schema overview."},
                        "limit": {"type": "integer", "default": 10}
                    }
                }
            })
            def create_handler(nk, path):
                def handler(args):
                    q = args.get("query", "")
                    lim = args.get("limit", 10)
                    if not q:
                        q = f"SELECT name, type FROM sqlite_master WHERE type='table' LIMIT {lim}"
                    return json.dumps(read_sqlite(path, q), indent=2)
                return handler
            TOOL_MAP[tool_name] = create_handler(name_key, db_path) # type: ignore
            count += 1
            results.append(f"  ✓ {app_name} ({db_path.name}, {peak} rows)")

    summary = f"Full walk complete: {count} new apps registered, {skipped_consent} deferred (consent required), {low_density} skipped (low density)."
    if results:
        summary += "\n\nRegistered:\n" + "\n".join(results)
    return summary

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
        return f"App '{app_name}' not found locally."

    # 3. Handle Encryption
    # (Encryption is now handled by auto-connector.ts via LDPBrain)
    
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
    {"name": "ldp_claude_history", "description": "Read Claude Desktop local sessions, MCP config, and agent-mode history.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer", "default": 20}, "query": {"type":"string", "description": "Optional text filter"}}}},
    {"name": "ldp_request_approvals", "description": "Re-prompt for access to any denied app categories.", "inputSchema": {"type":"object"}},
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
    "ldp_claude_history": lambda a: tool_claude_history(a.get("limit", 20), a.get("query", "")),
    "ldp_request_approvals": lambda a: tool_request_approvals(),
}

def main():
    sys.stderr.write("[LDP] Dynamic Server Starting...\n")
    
    # Run generic category approvals at startup if never asked
    approvals.run_first_run_approvals()
    
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
