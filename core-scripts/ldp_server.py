"""
LDP MCP Server — connects to Cursor via native MCP support.
Pure Python, zero dependencies beyond stdlib.
Reads: Chrome history, shell history, VS Code recent files,
       git log, terminal commands, any SQLite on your Mac.
"""

import sqlite3, shutil, os, json, sys, tempfile, subprocess, platform, glob
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Union, Dict, Any

# ── Common Paths & Global State ───────────────────────────────────
HOME = Path.home()
SCRIPT_DIR = Path(__file__).parent
# CORE_SCRIPTS is either alongside the server or in the parent directory
CORE_SCRIPTS = SCRIPT_DIR / "../core-scripts"
import importlib.abc
import hashlib
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from collections import deque

if not CORE_SCRIPTS.exists():
    CORE_SCRIPTS = SCRIPT_DIR / "core-scripts"

# --- Layer 2: Secure Network Sandbox ---
class NetworkSandboxFinder(importlib.abc.MetaPathFinder):
    BLOCKED_MODULES = {"requests", "urllib", "httpx", "http", "socket", "urllib3"}
    def find_spec(self, fullname, path, target=None):
        base_module = fullname.split(".")[0]
        if base_module in self.BLOCKED_MODULES:
            raise ImportError(f"LDP Network Sandbox Violation: Attempted to import '{fullname}'")
        return None

sys.meta_path.insert(0, NetworkSandboxFinder())

# --- Layers 1, 3, 5: Security Enforcer ---
AUDIT_LOG_FILE = HOME / ".ldp" / "audit.log"
TRUSTED_FILE = HOME / ".ldp" / "trusted.json"

class LDPSecurityEnforcer:
    def __init__(self):
        self.call_history = deque()
        self.rate_limit = 50
        self.rate_window = 60 # seconds
        self._setup_audit_log()
        self._load_trusted()

    def _setup_audit_log(self):
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            filename=str(AUDIT_LOG_FILE),
            level=logging.INFO,
            format='%(asctime)s | LDP_AUDIT | %(message)s'
        )

    def _load_trusted(self):
        if not TRUSTED_FILE.exists():
            TRUSTED_FILE.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(TRUSTED_FILE, "w") as f:
                    json.dump({"trusted_connectors": [], "policy": "allowlist_only"}, f, indent=2)
            except: pass

    def verify_connector(self, script_path: Path) -> bool:
        """Layer 1 & 3: Verifies SHA256 hash of a script against trusted.json."""
        if not script_path.exists(): return False
        with open(script_path, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        
        try:
            with open(TRUSTED_FILE, "r") as f:
                trusted = json.load(f)
        except: return False
        
        for c in trusted.get("trusted_connectors", []):
            if c.get("hash") == f"sha256:{h}":
                return True
        logging.warning(f"UNTRUSTED_CONNECTOR | {script_path.name} | hash: sha256:{h}")
        return False

    def log_call(self, tool_name: str, args: dict):
        """Layer 5: Logs call and applies 50 per 60s rate limit."""
        now = datetime.now(timezone.utc).timestamp()
        
        threshold = now - self.rate_window
        while self.call_history and self.call_history[0] < threshold:
            self.call_history.popleft()
            
        if len(self.call_history) >= self.rate_limit:
            logging.error(f"RATE_LIMIT_EXCEEDED | {tool_name} | dropped")
            raise Exception("Anomaly Detected: Rate Limit Exceeded (50 calls / 60 sec). LDP paused.")
            
        self.call_history.append(now)
        logging.info(f"TOOL_CALL | {tool_name} | ARGS: {json.dumps(args)}")

security_enforcer = LDPSecurityEnforcer()

# PLATFORM_PATHS removed in Phase 14 to allow for true auto-discovery.
# All data locations are now managed by brain_knowledge.json.
DYNAMIC_PATHS = {} # tool_name -> file_path

# ── Approval Management ──────────────────────────────────────────

CATEGORY_MAP = {
    "browser":       ["chrome", "brave", "firefox", "safari", "edge", "arc"],
    "communication": ["signal", "whatsapp", "imessage", "telegram", "messages"],
    "work":          ["slack", "zoom", "vscode", "cursor", "git", "jira", "linear", "teams", "webex", "pycharm", "calendar", "contacts"],
    "personal":      ["claude", "spotify", "notes", "animoji", "photos"],
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
                    data = json.load(f)
                for k, v in data.items():
                    if isinstance(v, str):
                        data[k] = {
                            "approved": (v == "approved"),
                            "asked_at": datetime.now(timezone.utc).isoformat(),
                            "revoked_at": None,
                            "can_retry": (v != "approved")
                        }
                if "__app_overrides__" not in data:
                    data["__app_overrides__"] = {}
                self.state = data
            except:
                self.state = {"__app_overrides__": {}}
        else:
            self.state = {"__app_overrides__": {}}

    def save(self):
        self.approvals_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            import tempfile, os
            fd, tmp = tempfile.mkstemp(dir=self.approvals_file.parent, prefix=".approvals.", suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump(self.state, f, indent=2)
            os.replace(tmp, self.approvals_file)
        except Exception as e:
            sys.stderr.write(f"[LDP] Error saving approvals: {e}\n")

    def is_app_denied(self, app_name: str, category: str) -> bool:
        overrides = self.state.get("__app_overrides__", {})
        if app_name in overrides:
            return not overrides[app_name].get("approved", True)
        return self.is_denied(category)

    def is_app_paused(self, app_name: str) -> bool:
        overrides = self.state.get("__app_overrides__", {})
        if app_name in overrides:
            return overrides[app_name].get("paused", False)
        return False

    def set_app_state(self, app_name: str, approved: bool, paused: bool):
        if "__app_overrides__" not in self.state:
            self.state["__app_overrides__"] = {}
        self.state["__app_overrides__"][app_name] = {
            "approved": approved,
            "paused": paused,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        self.save()

    def is_approved(self, category: str) -> bool:
        if category not in self.state: return False
        return self.state[category].get("approved", False)

    def is_denied(self, category: str) -> bool:
        if category not in self.state: return False
        return not self.state[category].get("approved", False)

    def has_asked(self, category: str) -> bool:
        return category in self.state

    def reset(self):
        self.state = {}
        if self.approvals_file.exists():
            try: os.unlink(self.approvals_file)
            except: pass

    def revoke(self, category: str):
        if category in self.state:
            self.state[category]["approved"] = False
            self.state[category]["revoked_at"] = datetime.now(timezone.utc).isoformat()
            self.state[category]["can_retry"] = True
            self.save()

    def request(self, category: str, auto_save: bool = True) -> str:
        """Prompt user via macOS dialog and store result."""
        if PLATFORM != "darwin":
            self.state[category] = {
                "approved": True,
                "asked_at": datetime.now(timezone.utc).isoformat(),
                "revoked_at": None,
                "can_retry": False
            }
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
            status = "approved" if "Allow" in res.stdout else "denied"
        except:
            status = "denied"

        self.state[category] = {
            "approved": (status == "approved"),
            "asked_at": datetime.now(timezone.utc).isoformat(),
            "revoked_at": None,
            "can_retry": (status == "denied")
        }
        if auto_save:
            self.save()
        return status

    def run_first_run_approvals(self):
        """Check if approvals.json exists. If not, prompt for the 5 categories."""
        if self.approvals_file.exists():
            return # RULE 1: If it DOES exist -> skip all dialogs completely

        for cat in CATEGORY_MAP.keys():
            self.request(cat, auto_save=False)
        self.save()

approvals = ApprovalManager()

# --- Layer 9: Dynamic Tool Discovery (Rules 1-11) ---

# PLATFORM_PATHS and SOURCES were removed in Phase 14.
# All app locations are now discovered by the Node.js scanner
# and registered in DYNAMIC_PATHS via the list-tools.ts bridge.


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
    """Read browser history from discovered browser databases."""
    paths = []
    for t in ["ldp_chrome_query", "ldp_brave_query", "ldp_edge_query"]:
        p = DYNAMIC_PATHS.get(t)
        if p and Path(p).exists(): paths.append(Path(p))
    
    if not paths:
        return "No browser history found (Chrome/Brave/Edge)."
    
    all_rows: List[Dict] = []
    for path in paths:
        try:
            # Browser history usually has a 'urls' table
            rows_data = read_sqlite(path, f"SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT {limit}")
            all_rows.extend(rows_data)
        except: continue
    
    if not all_rows: return "No history entries found."
    all_rows.sort(key=lambda x: x.get("visit_count", 0), reverse=True)
    
    out = [f"{'URL':<60} {'VISITS':>6}"]
    for r in all_rows[:limit]:
        url_str = str(r.get("url", ""))[:58]
        visits  = int(r.get("visit_count", 0))
        out.append(f"{url_str:<60} {visits:>6}")
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

def tool_imessage_history(limit: int = 50, query: str = "") -> str:
    """Read recent iMessage history using Apple's local SQLite database."""
    db_path = HOME / "Library/Messages/chat.db"
    if not db_path.exists():
        return "Error: chat.db not found. Ensure Full Disk Access is granted to your terminal/cursor."
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(db_path, tmp_path)
    except Exception as e:
        return f"Error copying chat.db: {e}"
        
    try:
        conn = sqlite3.connect(tmp_path)
        cur = conn.cursor()
        
        sql = '''
            SELECT h.id as sender, m.text, 
                   datetime(m.date/1000000000 + 978307200, 'unixepoch', 'localtime') as date
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            WHERE m.text IS NOT NULL
        '''
        if query: sql += " AND m.text LIKE ?"
        sql += " ORDER BY m.date DESC LIMIT ?"
        
        args = (f"%{query}%", limit) if query else (limit,)
        cur.execute(sql, args)
        rows = cur.fetchall()
        
        if not rows: return "No messages found."
            
        out = ["Recent iMessages:\n"]
        for sender, text, date in reversed(rows):
            sender_disp = sender if sender else "Me"
            snippet = text.replace('\n', ' ')
            if len(snippet) > 80: snippet = snippet[:77] + "..."
            out.append(f"[{date}] {sender_disp}: {snippet}")
        return "\n".join(out)
    except Exception as e:
        return f"Error querying iMessage: {e}"
    finally:
        try: os.unlink(tmp_path)
        except: pass

def tool_contacts_history(query: str = "") -> str:
    """Search Apple Contacts."""
    base_dir = HOME / "Library/Application Support/AddressBook/Sources"
    if not base_dir.exists(): return "Error: Contacts folder not found."
    
    results = []
    for db_path in base_dir.rglob("AddressBook-*.abcddb"):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            shutil.copy2(db_path, tmp_path)
            conn = sqlite3.connect(tmp_path)
            cur = conn.cursor()
            
            sql = '''
                SELECT ZABCDRECORD.ZFIRSTNAME, ZABCDRECORD.ZLASTNAME, ZABCDRECORD.ZORGANIZATION,
                       ZABCDEMAILADDRESS.ZADDRESS, ZABCDPHONENUMBER.ZFULLNUMBER
                FROM ZABCDRECORD
                LEFT JOIN ZABCDEMAILADDRESS ON ZABCDEMAILADDRESS.ZOWNER = ZABCDRECORD.Z_PK
                LEFT JOIN ZABCDPHONENUMBER ON ZABCDPHONENUMBER.ZOWNER = ZABCDRECORD.Z_PK
                WHERE ZABCDRECORD.ZFIRSTNAME IS NOT NULL OR ZABCDRECORD.ZLASTNAME IS NOT NULL
            '''
            cur.execute(sql)
            rows = cur.fetchall()
            
            for f, l, o, e, p in rows:
                name = list(filter(None, [f, l]))
                name_str = " ".join(name)
                if query and query.lower() not in name_str.lower() and (not e or query.lower() not in e.lower()):
                    continue
                
                details = []
                if o: details.append(f"Org: {o}")
                if e: details.append(f"Email: {e}")
                if p: details.append(f"Phone: {p}")
                results.append(f"{name_str} - " + ", ".join(details))
        except: pass
        finally:
            try: os.unlink(tmp_path)
            except: pass
            
    if not results: return "No contacts found."
    # Deduplicate and sort
    return "Contacts:\n" + "\n".join(sorted(list(set(results)))[:50])

def tool_calendar_history(limit: int = 50) -> str:
    """Read recent/upcoming Apple Calendar events."""
    db_path = HOME / "Library/Calendars/Calendar Cache"
    if not db_path.exists(): return "Error: Calendar Cache not found."
        
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(db_path, tmp_path)
    except: return "Error copying calendar db"
    
    try:
        conn = sqlite3.connect(tmp_path)
        cur = conn.cursor()
        
        sql = '''
            SELECT ZTITLE, 
                   datetime(ZSTARTDATE + 978307200, 'unixepoch', 'localtime') as start,
                   datetime(ZENDDATE + 978307200, 'unixepoch', 'localtime') as end,
                   ZLOCATION
            FROM ZCALENDARITEM
            WHERE ZTITLE IS NOT NULL
            ORDER BY ZSTARTDATE DESC
            LIMIT ?
        '''
        cur.execute(sql, (limit,))
        rows = cur.fetchall()
        
        if not rows: return "No events found."
        
        out = ["Calendar Events:\n"]
        for title, start, end, loc in rows:
            loc_str = f" at {loc}" if loc else ""
            out.append(f"[{start} to {end}] {title}{loc_str}")
        return "\n".join(out)
    except Exception as e: return f"Error reading Calendar: {e}"
    finally:
        try: os.unlink(tmp_path)
        except: pass

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
        results = [r for r in results if any(q in str(v).lower() for v in r.items())]
    
    if not results: return "No Claude session data found."
    out = [f"Claude Desktop Data ({len(results)} items found):\n"]
    for r in results[:limit]:
        rtype = r.get("type", "unknown")
        out.append(f"  [{rtype}] {r}")
    return "\n".join(out)

def tool_manage_approvals(action: str, category: str = "") -> str:
    """Manage category approvals."""
    global TOOLS, DISCOVERED_APPS
    
    if action == "reset":
        approvals.reset()
        return "Full reset complete. ~/.ldp/approvals.json deleted. Dialogs will reappear on next LDP start."
        
    elif action == "revoke":
        if not category or category not in CATEGORY_MAP: return f"Unknown or missing category: {category}"
        approvals.revoke(category)
        
        # Live unregister dynamic tools
        for name_key in list(DISCOVERED_APPS.keys()):
            if classify_app(name_key) == category:
                del DISCOVERED_APPS[name_key]
                
        # Rebuild TOOLS list excluding the revoked category
        tools_to_keep = []
        STATIC_MAP = {
            "ldp_chrome_history": "browser",
            "ldp_shell_history": "system",
            "ldp_claude_history": "personal",
        }
        for t in TOOLS:
            name = t["name"]
            if name in STATIC_MAP and STATIC_MAP[name] == category:
                continue # drop static tool from this category
            if name.startswith("ldp_") and name.endswith("_query"):
                name_key = name[4:-6]
                if classify_app(name_key) == category:
                    continue # drop dynamic tool from this category
            tools_to_keep.append(t)
            
        removed_count = len(TOOLS) - len(tools_to_keep)
        TOOLS[:] = tools_to_keep # in-place modification
        return f"Revoked '{category}'. {removed_count} tools instantly unregistered."
        
    elif action == "reapprove":
        if not category or category not in CATEGORY_MAP: return f"Unknown or missing category: {category}"
        if approvals.is_approved(category):
            return f"Category '{category}' is already approved."
        
        status = approvals.request(category)
        if status == "approved":
            tool_discover_apps() # Run discovery to instantly register
            return f"Re-approved '{category}'. Tools instantly registered."
        return f"Re-approval for '{category}' was denied."

    return "Invalid action. Use reset, revoke, or reapprove."

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
    ".macromedia", "Cookies", "CoreDataBackend", "TipKit", "Dock", "DriveFS"
]

def tool_whatsapp_query(args: dict) -> str:
    """Specialized handler for WhatsApp local data (readable only)."""
    wa_base1 = HOME / "Library/Group Containers/group.net.whatsapp.whatsapp.shared"
    wa_base2 = HOME / "Library/Group Containers/group.net.whatsapp.WhatsApp.shared"
    
    candidates = [
        wa_base2 / "ChatStorage.sqlite",
        wa_base1 / "CallHistory.sqlite",
        wa_base1 / "ContactsV2.sqlite",
        wa_base1 / "fts/ChatSearchV5f.sqlite"
    ]
    
    exists = [fp for fp in candidates if fp.exists()]
    if not exists: return "WhatsApp databases not found."

    query = args.get("query", "")
    limit = args.get("limit", 10)
    
    if query:
        for fp in exists:
            data = read_sqlite(fp, query)
            if data is not None:
                return f"WhatsApp Data ({fp.name}):\n" + json.dumps(data[:limit], indent=2)
        return "Query failed on all WhatsApp databases. Check table names or SQL syntax."
        
    results = []
    for fp in exists:
        try:
            tables = read_sqlite(fp, "SELECT name FROM sqlite_master WHERE type='table'")
            if not tables: continue
            best_table = None
            max_r = 0
            for t in [d['name'] for d in tables]:
                rc = read_sqlite(fp, f"SELECT count(*) as c FROM \"{t}\"")
                if rc and rc[0]['c'] > max_r:
                    max_r = rc[0]['c']
                    best_table = t
            
            if best_table:
                data = read_sqlite(fp, f"SELECT * FROM \"{best_table}\" LIMIT {limit}")
                results.append({ "file": fp.name, "rows": max_r, "sample": data })
        except: continue
        
    if not results: return "No readable WhatsApp databases found (or zero rows)."
    
    # Return result with most rows
    results.sort(key=lambda x: x['rows'], reverse=True)
    best = results[0]
    return f"WhatsApp Data ({best['file']}, {best['rows']} rows):\n" + json.dumps(best['sample'], indent=2)

def tool_signal_query(args: dict) -> str:
    """Signal database handler (Encrypted - requires consent gate)."""
    return "Signal database is protected by LDP Consent Gate. Decryption requires Signal passkey from local Keychain. Please use the LDP Dashboard to approve and unlock Signal data."

def tool_telegram_query(args: dict) -> str:
    """Telegram database handler."""
    tg_base = HOME / "Library/Group Containers"
    # Find any telegram-related container with a postbox db
    db_paths = list(tg_base.glob("*.org.telegram.Telegram-iOS/postbox/db/db_sqlite"))
    if not db_paths: return "Telegram database not found on this system."
    
    try:
        data = read_sqlite(db_paths[0], "SELECT * FROM sqlite_master WHERE type='table' LIMIT 20")
        return f"Telegram Schema Info (Found {len(data)} tables):\n" + json.dumps(data, indent=2)
    except Exception as e:
        return f"Error reading Telegram DB: {e}"

import zipfile

def check_for_new_exports():
    """Layered Integration: Scans ~/Downloads for valid platform exports & unzips them safely."""
    downloads = HOME / "Downloads"
    exports_dir = HOME / ".ldp" / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    
    if not downloads.exists(): return
    
    PATTERNS = {
        "claude": "personal",
        "instagram": "personal",
        "takeout": "communication",
        "twitter": "communication"
    }
    
    # Check / Extract loop
    for path in downloads.glob("*.zip"):
        name = path.stem.lower()
        matched = None
        for prefix in PATTERNS.keys():
            if name.startswith(prefix):
                matched = prefix
                break
                
        if not matched: continue
        category = PATTERNS[matched]
        
        target_dir = exports_dir / name
        if not target_dir.exists():
            try:
                with zipfile.ZipFile(path, 'r') as zip_ref:
                    zip_ref.extractall(target_dir)
                sys.stderr.write(f"[LDP] Auto-extracted {path.name}\n")
            except Exception as e:
                sys.stderr.write(f"[LDP] Failed to extract {path.name}: {e}\n")
                continue
                
        # Register in master list
        DISCOVERED_EXPORTS[name] = category
        
        # Make the generic query lambda for the master tooling map
        tool_name = f"ldp_export_{name.replace('-','_')}_query"
        TOOL_MAP[tool_name] = lambda a, t=target_dir: tool_export_search(t, a.get("query",""))

def tool_export_search(export_dir: Path, query: str = "") -> str:
    """Basic search over extracted JSON/TXT files in an export."""
    if not query: return "Please provide a query to search this export."
    results = []
    
    # Extremely basic text search over json/txt
    for filepath in export_dir.rglob("*"):
        if not filepath.is_file(): continue
        if filepath.suffix.lower() not in ['.json', '.txt', '.csv', '.html']: continue
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                if query.lower() in content.lower():
                    # context snippet
                    idx = content.lower().find(query.lower())
                    start = max(0, idx - 40)
                    end = min(len(content), idx + 80)
                    snippet = content[start:end].replace('\n', ' ')
                    results.append(f"Match in {filepath.name}: ...{snippet}...")
        except: pass
        
        if len(results) > 20: break
        
    if not results: return f"No matches found for '{query}' in export."
    return "\n".join(results)

def tool_discover_apps(at_startup: bool = False) -> str:
    """Invokes the Node-based scanner for Rule 1-7 auto-discovery."""
    if at_startup:
        if (HOME / ".ldp" / "brain_knowledge.json").exists():
            return "Knowledge Base Loaded."
        return "New machine detected. Run ldp_discover_apps to profile."

    try:
        # Run the full scanner
        subprocess.run(["npx", "tsx", str(CORE_SCRIPTS / "run-auto.ts")], cwd=str(CORE_SCRIPTS), capture_output=True)
        rebuild_tools()
        return "Auto-discovery completed! Dynamic connectors registered."
    except Exception as e:
        log_ldp_crash(f"Discovery failed: {e}")
        return f"Discovery failed: {e}"

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

ALL_STATIC_TOOLS = [
    {"name": "ldp_diagnostics", "description": "Check LDP server status and version.", "inputSchema": {"type":"object"}},
    {"name": "ldp_check_permissions", "description": "Check Mac Full Disk Access permissions.", "inputSchema": {"type":"object"}},
    {"name": "ldp_system_health", "description": "Check LDP health, logs, and crashes.", "inputSchema": {"type":"object"}},
    {"name": "ldp_global_search", "description": "Search across all local history/data.", "inputSchema": {"type":"object", "properties": {"query": {"type":"string"}}}},
    {"name": "ldp_query_app", "description": "Query any discovered app (Signal, Chrome etc)", "inputSchema": {"type":"object", "properties": {"app_name": {"type":"string"}, "query":{"type":"string"}}}},
    {"name": "ldp_discover_apps", "description": "Scan Mac for local data apps", "inputSchema": {"type":"object"}},
    {"name": "ldp_manage_approvals", "description": "Revoke, reapprove, or reset your LDP category approvals live.", "inputSchema": {"type":"object", "properties": {"action": {"type": "string", "enum": ["revoke", "reapprove", "reset"]}, "category": {"type": "string", "description": "The category (e.g., browser, system, work) for revoke/reapprove"}}}},
    {"name": "ldp_active_app", "description": "What app is active right now, window title, URL if browser, time in this app", "inputSchema": {"type":"object","properties":{}}},
    {"name": "ldp_screen_today", "description": "Time spent in every app today with percentages.", "inputSchema": {"type":"object","properties":{}}},
    {"name": "ldp_screen_history", "description": "Full timeline of app switches. Filter by app name with app parameter.", "inputSchema": {"type":"object","properties":{"limit":{"type":"number"},"app":{"type":"string"}}}},
    {"name": "ldp_context_now", "description": "Complete current context — active app + today summary + recent messages. LDP's awareness layer.", "inputSchema": {"type":"object","properties":{}}},
]

TOOLS = []

def make_tool_handler(tool_name):
    def handler(args):
        limit = args.get('limit', 20)
        try:
            import shutil, tempfile, sqlite3, os, json
            brain_path = os.path.expanduser(
                '~/Desktop/LDP/core-scripts/brain_knowledge.json')
            with open(brain_path) as f:
                brain = json.load(f)
            db_path = None
            for key, val in brain.get('learned', {}).items():
                if val.get('appName','').lower().replace(' ','_') \
                   in tool_name:
                    db_path = val.get('filePath','')
                    break
            if not db_path: return f"Not found: {tool_name}"
            tmp = tempfile.mktemp(suffix='.db')
            shutil.copy2(os.path.expanduser(db_path), tmp)
            conn = sqlite3.connect(tmp)
            cur = conn.cursor()
            tables = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            best,count = tables[0],0
            for t in tables:
                try:
                    n=cur.execute(
                        f"SELECT count(*) FROM [{t}]"
                    ).fetchone()[0]
                    if n>count: count,best=n,t
                except: pass
            rows=cur.execute(
                f"SELECT * FROM [{best}] LIMIT {limit}"
            ).fetchall()
            cols=[r[1] for r in cur.execute(
                f"PRAGMA table_info([{best}])"
            )]
            conn.close()
            os.unlink(tmp)
            out=f"{best}: {count} rows\n"
            out+=" | ".join(cols)+"\n---\n"
            for r in rows:
                out+=" | ".join(str(v)[:40] if v 
                                else '' for v in r)+"\n"
            return out
        except Exception as e:
            return f"Error: {e}"
    return handler

def rebuild_tools():
    """Live-rebuilds the TOOLS array exposed to MCP based on approvals/pauses."""
    global TOOLS, DYNAMIC_PATHS
    new_tools = []
    new_paths = {}
    
    STATIC_MAP = {
        "ldp_diagnostics": "system",
        "ldp_check_permissions": "system",
        "ldp_system_health": "system",
        "ldp_global_search": "system",
        "ldp_query_app": "system",
        "ldp_discover_apps": "system",
        "ldp_manage_approvals": "system",
    }
    
    # 1. Register base system tools
    for st in ALL_STATIC_TOOLS:
        cat = STATIC_MAP.get(st["name"], "unknown")
        if cat != "system":
            if approvals.is_app_denied(st["name"], cat) or approvals.is_app_paused(st["name"]): continue
        new_tools.append(st)
    
    # 2. Register dynamic apps from Brain
    try:
        res = subprocess.run(["npx", "tsx", str(CORE_SCRIPTS / "list-tools.ts")], cwd=str(CORE_SCRIPTS), capture_output=True, text=True)
        if res.returncode == 0:
            discovered = json.loads(res.stdout)
            for d in discovered:
                # Handle path expansion
                f_path = d['path'].replace("~", str(HOME))
                if "**" in f_path:
                    # Very simple glob approximation for the server
                    root = Path(f_path.split("**")[0])
                    pattern = f_path.split("**")[1].lstrip("/")
                    matches = list(root.glob(f"**/{pattern}")) if root.exists() else []
                    if matches: f_path = str(matches[0])
                
                t_name = f"ldp_{d['name']}_query"
                new_paths[t_name] = f_path
                cat = classify_app(d['name'])
                if approvals.is_app_denied(t_name, cat) or approvals.is_app_paused(t_name): continue
                new_tools.append({
                    "name": t_name,
                    "description": f"Query {d['app']} local data ({f_path})",
                    "inputSchema": {"type":"object", "properties": {"query": {"type":"string"}, "limit": {"type":"integer", "default": 10}}}
                })
    except Exception as e:
        sys.stderr.write(f"[LDP] rebuild_tools error: {e}\n")
        
    TOOLS[:] = new_tools
    DYNAMIC_PATHS.update(new_paths)
    
    # Auto-register handlers for all tools missing one
    for tool in TOOLS:
        if tool['name'] not in TOOL_MAP:
            TOOL_MAP[tool['name']] = make_tool_handler(tool['name'])

# ── Screen Watcher ─────────────────────────────────────────────────
import time as _time

class ScreenWatcher:
    def __init__(self):
        self.log_path = os.path.expanduser("~/.ldp/activity_log.jsonl")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self.running = False
        self.current = {"app": "", "window": "", "url": "", "since": _time.time()}
        self.last_app = ""
        self.app_start = _time.time()

    def start(self):
        self.running = True
        threading.Thread(target=self._watch, daemon=True).start()

    def _get_context(self):
        script = '''tell application "System Events"
    set frontApp to name of first application process whose frontmost is true
    set winTitle to ""
    try
        set winTitle to name of front window of process frontApp
    end try
    return frontApp & "|||" & winTitle
end tell'''
        try:
            r = subprocess.run(["osascript", "-e", script],
                               capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                parts = r.stdout.strip().split("|||")
                return {"app": parts[0].strip() if parts else "",
                        "window": parts[1].strip() if len(parts) > 1 else ""}
        except Exception:
            pass
        return None

    def _get_browser_url(self, app):
        if "Chrome" not in app and "Safari" not in app:
            return ""
        browser = "Google Chrome" if "Chrome" in app else "Safari"
        script = f'tell application "{browser}"\nif it is running then\nreturn URL of active tab of front window\nend if\nend tell'
        try:
            r = subprocess.run(["osascript", "-e", script],
                               capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception:
            pass
        return ""

    def _watch(self):
        while self.running:
            try:
                ctx = self._get_context()
                if ctx and ctx["app"]:
                    app = ctx["app"]
                    if app != self.last_app:
                        duration = int(_time.time() - self.app_start)
                        entry = {
                            "time": datetime.now().isoformat(),
                            "app": self.last_app,
                            "window": self.current.get("window", ""),
                            "url": self.current.get("url", ""),
                            "seconds": duration
                        }
                        if self.last_app:
                            with open(self.log_path, "a") as f:
                                f.write(json.dumps(entry) + "\n")
                        url = self._get_browser_url(app)
                        self.current = {"app": app, "window": ctx["window"],
                                        "url": url, "since": _time.time()}
                        self.last_app = app
                        self.app_start = _time.time()
                    else:
                        self.current["window"] = ctx["window"]
            except Exception:
                pass
            _time.sleep(3)

    def now(self):
        c = self.current
        secs = int(_time.time() - c.get("since", _time.time()))
        mins = secs // 60
        return {"app": c.get("app", ""), "window": c.get("window", ""),
                "url": c.get("url", ""), "duration": f"{mins}m {secs%60}s"}

    def today_summary(self):
        if not os.path.exists(self.log_path):
            return {}
        today = datetime.now().date().isoformat()
        app_times = {}
        with open(self.log_path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if e["time"].startswith(today):
                        app = e["app"]
                        app_times[app] = app_times.get(app, 0) + e.get("seconds", 0)
                except Exception:
                    pass
        current = self.now()
        if current["app"]:
            cur_secs = int(_time.time() - self.current.get("since", _time.time()))
            app_times[current["app"]] = app_times.get(current["app"], 0) + cur_secs
        return dict(sorted(app_times.items(), key=lambda x: -x[1]))

    def history(self, limit=50):
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path) as f:
            lines = f.readlines()
        entries = []
        for line in reversed(lines[-limit:]):
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
        return entries

    def rotate_log(self):
        if not os.path.exists(self.log_path):
            return
        cutoff = _time.time() - (30 * 86400)
        kept = []
        with open(self.log_path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    t = datetime.fromisoformat(e["time"]).timestamp()
                    if t > cutoff:
                        kept.append(line)
                except Exception:
                    pass
        with open(self.log_path, "w") as f:
            f.writelines(kept)

watcher = ScreenWatcher()

def tool_active_app(args):
    now = watcher.now()
    if not now["app"]:
        return "No active app detected (Accessibility permission may be needed)"
    out = f"Active app: {now['app']}\n"
    out += f"Window:     {now['window']}\n"
    out += f"Time in app: {now['duration']}\n"
    if now["url"]:
        out += f"URL:        {now['url']}\n"
    return out

def tool_screen_today(args):
    summary = watcher.today_summary()
    if not summary:
        return "No activity recorded today yet. Watcher started at server launch."
    out = "Time spent today:\n\n"
    total = sum(summary.values())
    for app, secs in summary.items():
        mins = secs // 60
        hrs = mins // 60
        pct = int((secs / total) * 100) if total else 0
        time_str = f"{hrs}h {mins%60}m" if hrs > 0 else f"{mins}m"
        out += f"  {app}: {time_str} ({pct}%)\n"
    total_hrs = total // 3600
    total_mins = (total % 3600) // 60
    out += f"\nTotal tracked: {total_hrs}h {total_mins}m"
    return out

def tool_screen_history(args):
    limit = int(args.get("limit", 30))
    app_filter = args.get("app", "").lower()
    entries = watcher.history(limit)
    if not entries:
        return "No screen history yet. Watcher logs app switches to ~/.ldp/activity_log.jsonl."
    out = "Recent activity:\n\n"
    for e in entries:
        if app_filter and app_filter not in e.get("app", "").lower():
            continue
        secs_total = e.get("seconds", 0)
        mins = secs_total // 60
        secs = secs_total % 60
        t = e["time"][11:16]
        app = e.get("app", "")
        win = e.get("window", "")[:35]
        url = e.get("url", "")[:50]
        out += f"{t}  {app}  {mins}m{secs}s"
        if win:
            out += f"  [{win}]"
        if url:
            out += f"\n      {url}"
        out += "\n"
    return out

def tool_context_now(args):
    now = watcher.now()
    app = now.get("app", "")
    context = "RIGHT NOW:\n"
    context += f"App:      {app}\n"
    context += f"Window:   {now.get('window', '')}\n"
    if now.get("url"):
        context += f"URL:      {now['url']}\n"
    context += f"Time in app: {now.get('duration', '')}\n\n"

    today = watcher.today_summary()
    context += "TODAY SO FAR:\n"
    for a, secs in list(today.items())[:5]:
        context += f"  {a}: {secs//60}m\n"

    try:
        msg_db = os.path.expanduser("~/Library/Messages/chat.db")
        tmp = tempfile.mktemp(suffix=".db")
        shutil.copy2(msg_db, tmp)
        conn = sqlite3.connect(tmp)
        rows = conn.execute("""
            SELECT text FROM message
            WHERE text IS NOT NULL
            AND date > (strftime('%s','now')-86400-978307200)*1000000000
            ORDER BY date DESC LIMIT 5
        """).fetchall()
        conn.close()
        os.unlink(tmp)
        if rows:
            context += "\nRECENT MESSAGES:\n"
            for r in rows:
                if r[0]:
                    context += f"  {str(r[0])[:60]}\n"
    except Exception:
        pass

    try:
        hist = watcher.history(20)
        recent_apps = list(dict.fromkeys([e["app"] for e in hist if e.get("app")]))[:5]
        if recent_apps:
            context += f"\nRECENT APPS: {', '.join(recent_apps)}\n"
    except Exception:
        pass

    return context

TOOL_MAP = {
    "ldp_diagnostics": lambda a: tool_diagnostics(),
    "ldp_check_permissions": lambda a: tool_check_permissions(),
    "ldp_system_health": lambda a: tool_system_health(),
    "ldp_global_search": lambda a: tool_global_search(a.get("query","")),
    "ldp_query_app": lambda a: tool_query_app(a.get("app_name",""), a.get("query","")),
    "ldp_discover_apps": lambda a: tool_discover_apps(),
    "ldp_manage_approvals": lambda a: tool_manage_approvals(a.get("action",""), a.get("category", "")),
    "ldp_whatsapp_query": lambda a: tool_whatsapp_query(a),
    "ldp_signal_query": lambda a: tool_signal_query(a),
    "ldp_telegram_query": lambda a: tool_telegram_query(a),
    "ldp_active_app": tool_active_app,
    "ldp_screen_today": tool_screen_today,
    "ldp_screen_history": tool_screen_history,
    "ldp_context_now": tool_context_now,
}

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
        
    def do_GET(self):
        if self.path == "/api/connectors":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            
            d_state = { "tools": {} }
            
            def add_tool_state(name, cat):
                # Using our overrides or category approvals
                approved = not approvals.is_app_denied(name, cat)
                paused = approvals.is_app_paused(name)
                # Check category directly if no override
                can_retry = True
                if hasattr(approvals, "state"):
                    cat_state = approvals.state.get(cat, {})
                    can_retry = cat_state.get("can_retry", True)
                    
                overrides = approvals.state.get("__app_overrides__", {})
                if name in overrides:
                    can_retry = overrides[name].get("can_retry", True)
                
                d_state["tools"][name] = {
                    "name": name, "category": cat,
                    "approved": approved,
                    "paused": paused,
                    "can_retry": can_retry
                }
            
            # Fetch tools via the same bridge
            try:
                res = subprocess.run(["npx", "tsx", str(CORE_SCRIPTS / "list-tools.ts")], cwd=str(CORE_SCRIPTS), capture_output=True, text=True)
                if res.returncode == 0:
                    discovered = json.loads(res.stdout)
                    for d in discovered:
                        name = f"ldp_{d['name']}_query"
                        cat = classify_app(d['name'])
                        add_tool_state(name, cat)
            except: pass
            
            self.wfile.write(json.dumps(d_state).encode())
            
        elif self.path == "/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_cors_headers()
            self.end_headers()
            
            html = """<!DOCTYPE html>
<html><head><title>LDP Dashboard</title>
<style>
    body { font-family: system-ui, sans-serif; background: #0a0a0a; color: #eee; max-width: 800px; margin: 40px auto; }
    .tool-row { display: flex; justify-content: space-between; align-items: center; padding: 18px; background: #161616; margin-bottom: 12px; border-radius: 8px; border: 1px solid #333; }
    .tool-name { font-weight: 600; font-size: 17px; }
    .tool-cat { font-size: 13px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
    .btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-weight: 700; font-size: 13px; margin-left: 8px; transition: 0.1s opacity; }
    .btn:hover { opacity: 0.8; }
    .btn-on { background: #1ecc66; color: #000; }
    .btn-off { background: #ff4b4b; color: #fff; }
    .btn-pause { background: #f1c40f; color: #000; }
    .btn-orange { background: #e67e22; color: #fff; }
    .btn-gray { background: #555; color: #fff; }
    .status { margin-right: 20px; font-weight: 700; font-size: 14px; display: inline-block; width: 100px; text-align: right; }
    .on-text { color: #1ecc66; }
    .off-text { color: #ff4b4b; }
    .paused-text { color: #f1c40f; }
    .gray-text { color: #888; }
</style>
</head><body>
    <h1 style="margin-bottom:5px;">LDP Dashboard</h1>
    <p style="color:#888; margin-bottom: 30px;">Manage your local standard connectors live.</p>
    <div id="tools"></div>
    <script>
        async function fetchState() {
            const res = await fetch('/api/connectors');
            const data = await res.json();
            const container = document.getElementById('tools');
            container.innerHTML = '';
            
            const sections = {
                "browser": { title: "Browser", tools: [] },
                "communication": { title: "Communication", tools: [] },
                "work": { title: "Work", tools: [] },
                "personal": { title: "Personal", tools: [] },
                "exports": { title: "Exports", tools: [] }
            };
            
            for (const [name, info] of Object.entries(data.tools)) {
                let cat = info.category.toLowerCase();
                if (!sections[cat]) sections[cat] = { title: info.category, tools: [] };
                sections[cat].tools.push({name, info});
            }
            
            for (const [cat, section] of Object.entries(sections)) {
                if (section.tools.length === 0) continue;
                
                const secDiv = document.createElement('div');
                secDiv.innerHTML = `<h2 style="margin-top: 30px; font-size: 16px; color: #aaa; border-bottom: 1px solid #333; padding-bottom: 8px;">${section.title}</h2>`;
                container.appendChild(secDiv);
                
                for (const item of section.tools) {
                    const {name, info} = item;
                    
                    let statusText = '';
                    let actionBtns = '';
                    
                    if (info.approved && !info.paused) {
                        statusText = '<span class="status on-text">ON ●</span>';
                        actionBtns = `
                            <button class="btn btn-pause" onclick="postAction('/api/pause', '${name}')">PAUSE ⏸</button>
                            <button class="btn btn-off" onclick="revokeAction('${name}')">REVOKE ⨉</button>
                        `;
                    } else if (info.approved && info.paused) {
                        statusText = '<span class="status paused-text">PAUSED ⏸</span>';
                        actionBtns = `
                            <button class="btn btn-on" onclick="postAction('/api/resume', '${name}')">RESUME ▶</button>
                            <button class="btn btn-off" onclick="revokeAction('${name}')">REVOKE ⨉</button>
                        `;
                    } else if (!info.approved && info.can_retry) {
                        statusText = '<span class="status off-text" style="color:#e67e22;">OFF ○</span>';
                        actionBtns = `<button class="btn btn-orange" onclick="postAction('/api/approve', '${name}')">RE-ENABLE?</button>`;
                    } else {
                        statusText = '<span class="status gray-text">OFF ○</span>';
                        actionBtns = `<button class="btn btn-gray" onclick="postAction('/api/approve', '${name}')">ENABLE</button>`;
                    }
                    
                    const pretty = name.replace('ldp_', '').replace('_query', '').replace('_history', '').replace(/_/g, ' ');
                    const prettyUpper = pretty.charAt(0).toUpperCase() + pretty.slice(1);
                    
                    const row = document.createElement('div');
                    row.className = 'tool-row';
                    if (!info.approved) row.style.opacity = '0.5';
                    
                    row.innerHTML = `
                        <div>
                            <div class="tool-name">${prettyUpper}</div>
                            <div class="tool-cat" style="display:none;">${info.category}</div>
                        </div>
                        <div style="display:flex; align-items:center;">
                            ${statusText}
                            ${actionBtns}
                        </div>
                    `;
                    secDiv.appendChild(row);
                }
            }
        }
        
        async function postAction(endpoint, name) {
            await fetch(endpoint, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name}) });
            fetchState();
        }
        
        async function revokeAction(name) {
            if (confirm(`Are you sure you want to revoke access to ${name}?`)) {
                await postAction('/api/revoke', name);
            }
        }
        
        setInterval(fetchState, 3000);
        fetchState();
    </script>
</body></html>"""
            self.wfile.write(html.encode())

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(length).decode()) if length > 0 else {}
        name = data.get("name")
        
        if self.path == "/api/approve":
            approvals.set_app_state(name, approved=True, paused=False)
            if "__app_overrides__" in approvals.state and name in approvals.state["__app_overrides__"]:
                approvals.state["__app_overrides__"][name]["can_retry"] = False
                approvals.save()
        elif self.path == "/api/pause":
            approvals.set_app_state(name, approved=True, paused=True)
        elif self.path == "/api/resume":
            approvals.set_app_state(name, approved=True, paused=False)
        elif self.path == "/api/revoke":
            approvals.set_app_state(name, approved=False, paused=False)
            if "__app_overrides__" in approvals.state and name in approvals.state["__app_overrides__"]:
                approvals.state["__app_overrides__"][name]["can_retry"] = True
                approvals.save()
        
        rebuild_tools()
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

def start_dashboard_server():
    server = None
    port = 8765
    for p in range(8765, 8771):
        try:
            server = HTTPServer(('127.0.0.1', p), DashboardHandler)
            port = p
            break
        except Exception:
            pass
            
    if not server:
        sys.stderr.write("[LDP] Dashboard server failed to bind to any port in 8765-8770\n")
        return
        
    try:
        port_file = HOME / ".ldp" / "dashboard_port"
        port_file.parent.mkdir(parents=True, exist_ok=True)
        port_file.write_text(str(port))
    except Exception:
        pass
        
    threading.Thread(target=server.serve_forever, daemon=("--dashboard" not in sys.argv)).start()
    if "--dashboard" not in sys.argv:
        sys.stderr.write(f"[LDP] Dashboard hosted on http://127.0.0.1:{port}\n")

def main():
    sys.stderr.write("[LDP] Dynamic Server Starting...\n")
    start_dashboard_server()

    
    approvals.run_first_run_approvals()

    # Run Export Watcher ingestion at startup
    check_for_new_exports()

    # Run discovery at startup to populate DISCOVERED_APPS
    tool_discover_apps(at_startup=True)
    
    # Compile the live list of valid apps exposed to AI
    rebuild_tools()

    # Start screen watcher daemon (Accessibility API, no recording)
    watcher.start()
    watcher.rotate_log()
    sys.stderr.write("[LDP] Screen watcher started → ~/.ldp/activity_log.jsonl\n")
    
    if "--dashboard" in sys.argv:
        try:
            with open(HOME / ".ldp" / "dashboard_port", "r") as f:
                port = f.read().strip()
                sys.stderr.write(f"[LDP] Dashboard hosted on http://127.0.0.1:{port}\n")
        except: pass
        sys.stderr.write("[LDP] Running in dedicated dashboard mode (MCP disabled)\n")
        import time
        while True: time.sleep(1000)
    
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
                    # Layer 5 Security Audit + Rate Limiting
                    security_enforcer.log_call(name, args)
                    
                    res = TOOL_MAP[name](args)
                    json.dump({"jsonrpc":"2.0", "id":rid, "result": {"content": [{"type":"text", "text": str(res)}]}}, sys.stdout)
                except Exception as e:
                    json.dump({"jsonrpc":"2.0", "id":rid, "result": {"content": [{"type":"text", "text": f"Error: {e}"}], "isError": True}}, sys.stdout)
                print(flush=True)
            sys.stdout.write("\n"); sys.stdout.flush()
        except: pass

if __name__ == "__main__": main()
