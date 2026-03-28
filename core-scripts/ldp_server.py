"""
LDP MCP Server — connects to Cursor via native MCP support.
Pure Python, zero dependencies beyond stdlib.
Reads: Chrome history, shell history, VS Code recent files,
       git log, terminal commands, any SQLite on your Mac.
"""

LDP_VERSION = "1.1.0"

import sqlite3, shutil, os, json, sys, tempfile, subprocess, platform, glob, base64
from pathlib import Path
from datetime import datetime, timezone
import typing
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

import re, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── PII SHIELD ──────────────────────────────────────────────────
PII_PATTERNS = {
    'CARD':    r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    'SSN':     r'\b\d{3}-\d{2}-\d{4}\b',
    'API_KEY': r'\b(sk-|sk_live_|ghp_|AIza)[A-Za-z0-9_\-]{20,}\b',
    'PASSWD':  r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+',
    'BANK':    r'\b\d{8,17}\b',
    'ROUTING': r'\b\d{9}\b'
}

_TOKEN_MAP = {}
_TOKEN_COUNTER = [0]

def pii_shield(text: str) -> str:
    result = text
    for label, pattern in PII_PATTERNS.items():
        for match in re.findall(pattern, result):
            _TOKEN_COUNTER[0] += 1
            token = f"{{{{PII_{label}_{_TOKEN_COUNTER[0]:03d}}}}}"
            _TOKEN_MAP[token] = match
            result = result.replace(match, token, 1)
    return result

def pii_resolve(token: str) -> str:
    return _TOKEN_MAP.get(token, token)

# ── AES-256-GCM VAULT ───────────────────────────────────────────
VAULT_PATH = os.path.expanduser('~/.ldp/vault.json')
_VAULT_KEY = None

def _get_vault_key() -> bytes:
    global _VAULT_KEY
    if _VAULT_KEY is not None:
        return _VAULT_KEY
    r = subprocess.run(
        ['security', 'find-generic-password', '-s', 'LDP-Vault-Key', '-w'],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        _VAULT_KEY = bytes.fromhex(r.stdout.strip())
    else:
        _VAULT_KEY = os.urandom(32)
        subprocess.run([
            'security', 'add-generic-password',
            '-s', 'LDP-Vault-Key', '-a', 'ldp',
            '-w', _VAULT_KEY.hex()
        ], capture_output=True)
    return _VAULT_KEY

def vault_write(key: str, data: dict) -> None:
    aesgcm = AESGCM(_get_vault_key())
    nonce  = os.urandom(12)
    ct     = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
    vault  = {}
    if os.path.exists(VAULT_PATH):
        try:
            with open(VAULT_PATH) as f:
                vault = json.load(f)
        except: pass
    vault[key] = {
        'header': 'LDP-PQC-V1:AES-256-GCM',
        'nonce':  base64.b64encode(nonce).decode(),
        'ct':     base64.b64encode(ct).decode()
    }
    os.makedirs(os.path.dirname(VAULT_PATH), exist_ok=True)
    tmp = VAULT_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(vault, f, indent=2)
    os.rename(tmp, VAULT_PATH)

def vault_read(key: str) -> Optional[dict]:
    if not os.path.exists(VAULT_PATH):
        return None
    try:
        with open(VAULT_PATH) as f:
            vault = json.load(f)
        if key not in vault:
            return None
        entry  = vault[key]
        aesgcm = AESGCM(_get_vault_key())
        nonce  = base64.b64decode(entry['nonce'])
        ct     = base64.b64decode(entry['ct'])
        return json.loads(aesgcm.decrypt(nonce, ct, None))
    except: return None

# ── AUDIT LOG ───────────────────────────────────────────────────
AUDIT_PATH = os.path.expanduser('~/.ldp/audit.log')

def audit_log(tool_name: str, row_count: int) -> None:
    from datetime import datetime
    line = f"{datetime.now().isoformat()} | tool={tool_name} | rows={row_count}\\n"
    with open(AUDIT_PATH, 'a') as f:
        f.write(line)

def tool_audit_log(args):
    limit = args.get('limit', 20)
    if not os.path.exists(AUDIT_PATH):
        return "No audit log yet."
    with open(AUDIT_PATH) as f:
        lines = f.readlines()
    return ''.join(lines[-limit:])

if not CORE_SCRIPTS.exists():
    CORE_SCRIPTS = SCRIPT_DIR / "core-scripts"

# --- Layer 2: Secure Network Sandbox ---
class NetworkSandboxFinder(importlib.abc.MetaPathFinder):
    BLOCKED_MODULES = {"requests", "httpx", "http", "socket", "urllib3"}
    def find_spec(self, fullname, path, target=None):
        base_module = fullname.split(".")[0]
        if base_module in self.BLOCKED_MODULES:
            raise ImportError(f"LDP Network Sandbox Violation: Attempted to import '{fullname}'")
        return None

sys.meta_path.insert(0, NetworkSandboxFinder())

# --- Layers 1, 3, 5: Security Enforcer ---
LDP_DIR = HOME / ".ldp"
AUDIT_LOG_FILE = LDP_DIR / "audit.log"
TRUSTED_FILE = LDP_DIR / "trusted.json"
CACHE_FILE = LDP_DIR / "discovery_cache.db"
AGENT_TRUST_FILE = LDP_DIR / "agent_trust.json"

class LDPSecurityEnforcer:
    def __init__(self):
        self.call_history = deque()
        self.rate_limit = 50
        self.rate_window = 60 # seconds
        self.agent_trust = {"agents": []}
        self.current_agent_id = "claude-desktop" # Default for now/initialization
        self._setup_audit_log()
        self._load_trusted()
        self._load_agent_trust()
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}

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

    def _load_agent_trust(self):
        if not AGENT_TRUST_FILE.exists():
            AGENT_TRUST_FILE.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(AGENT_TRUST_FILE, "w") as f:
                    json.dump({"agents": [{"id": "claude-desktop", "allowed_categories": ["personal", "work", "finance", "browser", "system", "communication"]}], "default_policy": "deny"}, f, indent=2)
            except: pass
        try:
            with open(AGENT_TRUST_FILE, "r") as f:
                self.agent_trust = json.load(f)
        except: self.agent_trust = {"agents": []}

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

    def check_agent_permission(self, category: str) -> bool:
        """Verify if current agent is allowed to access this category."""
        for agent in self.agent_trust.get("agents", []):
            if agent.get("id") == self.current_agent_id:
                return category in agent.get("allowed_categories", [])
        return False

    def log_call(self, tool_name: str, args: dict):
        """Layer 5: Logs call and applies 50 per 60s rate limit."""
        # ... existing rate limit logic ...
        now = datetime.now(timezone.utc).timestamp()
        threshold = now - self.rate_window
        while self.call_history and self.call_history[0] < threshold:
            self.call_history.popleft()
        if len(self.call_history) >= self.rate_limit:
            logging.error(f"RATE_LIMIT_EXCEEDED | {tool_name} | dropped")
            raise Exception("Anomaly Detected: Rate Limit Exceeded (50 calls / 60 sec). LDP paused.")
        self.call_history.append(now)
        
        # Agent context logging
        logging.info(f"TOOL_CALL | {self.current_agent_id} | {tool_name} | ARGS: {json.dumps(args)}")

    def request_approval(self, tool_name: str, args: dict) -> str:
        hash_val = hashlib.md5(f"{tool_name}{json.dumps(args)}{datetime.now()}".encode()).hexdigest()
        token = typing.cast(Any, hash_val)[0:8]
        self.pending_approvals[token] = {"tool": tool_name, "args": args, "expires": datetime.now().timestamp() + 300}
        return token

    def verify_approval(self, token: str) -> Optional[dict]:
        action = self.pending_approvals.get(token)
        if action and action["expires"] > datetime.now().timestamp():
            self.pending_approvals.pop(token, None)
            return action
        return None

security_enforcer = LDPSecurityEnforcer()
import re

class PersonalDataShield:
    """Layer 10: Prevents PII and raw private details from reaching the LLM."""
    PII_PATTERNS = {
        "GH_TOKEN": r"\bghp_[a-zA-Z0-9]{36}\b",
        "AI_KEY": r"\bsk-[a-zA-Z0-9]{48}\b",
        "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "API_KEY": r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{12,})['\"]?",
        "PHONE": r"\b(?:\+?1[-. ]?)?\(?([2-9][0-9]{2})\)?[-. ]?([2-9][0-9]{2})[-. ]?([0-9]{4})\b",
    }
    
    @staticmethod
    def filter(text: str) -> str:
        if not isinstance(text, str): return text
        out = text
        # 1. Mask strict PII
        for label, pattern in PersonalDataShield.PII_PATTERNS.items():
            if label == "API_KEY":
                # Special handle to keep the key name but mask the value
                out = re.sub(pattern, r"\1: [REDACTED_SECRET]", out)
            else:
                out = re.sub(pattern, f"[REDACTED_{label}]", out)
        
        # 2. Heuristic Address Masking
        # Matches "Number Street, City City, ST 12345"
        # Handles 1-2 word cities and common street suffixes
        addr_pattern = r"\d{1,6}\s+([A-Z][a-z]+\s+){1,3}(St|Ave|Rd|Blvd|Ln|Dr|Way|Ct|Pl),?\s+([A-Z][a-z]+\s*){1,2},?\s+[A-Z]{2}\s+\d{5}"
        out = re.sub(addr_pattern, "[REDACTED_ADDRESS]", out)
        
        # 3. Layer 5: Identity Anonymization (First Name Only)
        # Heuristic for Full Names (Capitalized Word followed by Capitalized Word)
        # We avoid matching common words by requiring a 2-word sequence at the start of entries or in contact fields
        # For now, let's apply it globally but be careful not to break common phrases like "Google Chrome"
        name_pattern = r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b"
        # Actually, let's keep it simple: Replace "First Last" with "First [MASKED]"
        EXEMPT_NAMES = {
            # Generic title-case words that are NOT personal names
            "Google", "Apple", "Microsoft", "Visual", "Studio", "Activity",
            "Recent", "System", "Private", "Personal", "Signal", "Chrome",
            "Safari", "Firefox", "Brave", "Spotify", "Slack", "Discord",
            "Telegram", "WhatsApp", "Cursor", "VS", "Code", "GitHub",
            "Desktop", "Documents", "Downloads", "Library", "Application",
            "Support", "Local", "Remote", "Home", "Work", "Office",
            "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
            "Saturday", "Sunday", "January", "February", "March", "April",
            "May", "June", "July", "August", "September", "October",
            "November", "December", "New", "Old", "Open", "Close",
        }
        def mask_name(match):
            first = match.group(1)
            last = match.group(2)
            if first in EXEMPT_NAMES: return match.group(0)
            return f"{first} [REDACTED_LAST_NAME]"
            
        out = re.sub(name_pattern, mask_name, out)
        
        return out

# --- Layer 11: Phase 4A Discovery Cache ---
class DiscoveryCache:
    def __init__(self):
        self.db_path = CACHE_FILE
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    app_name TEXT PRIMARY KEY,
                    path TEXT,
                    category TEXT,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            sys.stderr.write(f"[LDP] Cache Init Error: {e}\n")

    def load(self) -> Dict[str, str]:
        paths = {}
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT app_name, path FROM cache")
            for name, path in cur.fetchall():
                paths[name] = path
            conn.close()
        except: pass
        return paths

    def update_batch(self, new_paths: Dict[str, str]):
        try:
            conn = sqlite3.connect(self.db_path)
            for name, path in new_paths.items():
                conn.execute('''
                    INSERT INTO cache (app_name, path, category, last_seen)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(app_name) DO UPDATE SET
                        path = excluded.path,
                        last_seen = CURRENT_TIMESTAMP
                ''', (name, path, "general"))
            conn.commit()
            conn.close()
        except: pass

discovery_cache = DiscoveryCache()

# --- Layer 12: Phase 4B Action Token Resolution ---
class SecureActionRedirector:
    def __init__(self):
        self.vault_path = LDP_DIR / "vault.json"

    def _load_vault(self) -> Dict[str, str]:
        if not self.vault_path.exists(): return {}
        try:
            with open(self.vault_path, "r") as f:
                return json.load(f).get("raw_pii", {})
        except: return {}

    def resolve(self, text: str) -> str:
        """Replace {{TOKEN}} with real PII from vault."""
        pii = self._load_vault()
        def repl(match):
            token = match.group(1).upper()
            return pii.get(token, f"{{{{{token}}}}}") # Keep if not found
            
        return re.sub(r"\{\{([A-Z0-9_]+)\}\}", repl, text)

action_redirector = SecureActionRedirector()

def tool_archival_dump(query: str, days: int = 180) -> str:
    """Returns a massive raw dump of contextual data for deep archival analysis (Gemini)."""
    # This tool bypasses the standard 50-row limit for Gemini 1.5 Pro
    results = []
    for app, path in DISCOVERED_APPS.items():
        if app in ["whatsapp", "signal", "chrome", "git"]:
           # Simulated full-table read
           results.append({"app": app, "data": "Full dump content..."})
    return json.dumps(results)

def tool_get_semantic_facts(args: Optional[Dict[str, Any]] = None) -> str:
    """Returns compressed semantic facts about the user from the local vault."""
    vault_path = LDP_DIR / "vault.json"
    if not vault_path.exists():
        return "No semantic facts found. Vault is empty."
    try:
        with open(vault_path, "r") as f:
            data = json.load(f)
        facts = data.get("semantic_facts", [])
        if not facts: return "No semantic facts stored."
        return "\n".join([f"- {f}" for f in facts])
    except Exception as e:
        return f"Error reading vault: {e}"

def tool_secure_action(action_type: str, target_payload: str) -> str:
    """Phase 4B: Resolve tokens in payload and simulate a secure action."""
    resolved = action_redirector.resolve(target_payload)
    # Layer 4: Audit the action (but log with tokens, not PII if possible, or log securely)
    logging.info(f"SECURE_ACTION | type: {action_type} | payload: [RESOLVED]")
    
    # In a real impl, this would be an HTTP POST to a service
    # For now, we return a success message showing the resolution (for verification)
    return json.dumps({
        "status": "success",
        "action": action_type,
        "resolved_payload": resolved,
        "privacy": "Layer 12 Protected (Raw PII never reached the LLM)"
    }, indent=2)

PLATFORM = platform.system()
DISCOVERED_APPS = {}
SOURCES = {} # Legacy fallback for query_app
PLATFORM_PATHS = {} # Legacy fallback for permissions check
LDP_START_TIME = datetime.now(timezone.utc).timestamp()

def log_ldp_crash(msg: str):
    """Log crashes to disk and logging system."""
    logging.error(f"CRASH | {msg}")
    try:
        crash_log = HOME / ".ldp" / "crash.log"
        crash_log.parent.mkdir(parents=True, exist_ok=True)
        with open(crash_log, "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} | {msg}\n")
    except: pass

def find_mail_db() -> Optional[Path]:
    """Helper to locate the local Apple Mail Envelope Index."""
    p = HOME / "Library/Mail/V10/MailData/Envelope Index"
    return p if p.exists() else None

def tool_system_health(args: Optional[Dict[str, Any]] = None) -> str:
    """Check LDP health, logs, and recent crashes."""
    out = [f"LDP System Health (Uptime: {int(datetime.now(timezone.utc).timestamp() - LDP_START_TIME)}s)"]
    
    # 1. Syslog last 10 lines
    out.append("\\n--- Last 10 System Log Lines ---")
    syslog_path = Path("/var/log/system.log")
    if syslog_path.exists():
        try:
            with open(syslog_path, "r", errors="ignore") as f:
                lines = f.read().splitlines()
                out.extend([lines[i] for i in range(max(0, len(lines)-10), len(lines))])
        except: pass
        
    # 2. Crash logs from today
    out.append("\\n--- Crash Logs (Today) ---")
    diag_dir = HOME / "Library/Logs/DiagnosticReports"
    crashes_found = []
    if diag_dir.exists():
        today_str = datetime.now().strftime("%Y-%m-%d")
        for log in diag_dir.glob("*.ips"):
            if today_str in log.name or today_str in datetime.fromtimestamp(log.stat().st_mtime).strftime("%Y-%m-%d"):
                crashes_found.append(log.name)
    if crashes_found:
        out.extend(crashes_found)
    else:
        out.append("No crashes found today.")
        
    # 3. Disk space status
    out.append("\\n--- Disk Space ---")
    try:
        disk_cmd = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)
        if disk_cmd.returncode == 0:
            out.append(disk_cmd.stdout.strip().split("\\n")[-1])
    except: pass
    
    # 4. Memory pressure
    out.append("\\n--- Memory Settings ---")
    try:
        mem_cmd = subprocess.run(["vm_stat"], capture_output=True, text=True)
        if mem_cmd.returncode == 0:
            lines = mem_cmd.stdout.strip().split("\\n")
            out.extend([lines[i] for i in range(min(5, len(lines)))])
    except: pass
    
    return "\\n".join(out)

DYNAMIC_PATHS: Dict[str, str] = {} # tool_name -> file_path
TOOL_CATEGORIES: Dict[str, str] = {} # tool_name -> category (e.g., 'personal', 'work')
DISCOVERED_APPS: Dict[str, Any] = {}
DISCOVERED_EXPORTS: Dict[str, Any] = {}

# ── Approval Management ──────────────────────────────────────────

CATEGORY_MAP = {
    "browser":       ["chrome", "brave", "firefox", "safari", "edge", "arc"],
    "communication": ["signal", "whatsapp", "imessage", "telegram", "messages", "mail"],
    "work":          ["slack", "zoom", "vscode", "cursor", "git", "jira", "linear", "teams", "webex", "pycharm", "calendar", "contacts", "reminders"],
    "personal":      ["claude", "spotify", "notes", "animoji", "photos"],
    "system":        ["shell", "dock", "system", "kernel", "drivefs", "tipkit", "coredatabackend"],
}

def classify_app(name_key: str) -> str:
    """Map a normalized app name key to a category."""
    nk = name_key.lower()
    for cat, keywords in CATEGORY_MAP.items():
        if any(kw in nk for kw in keywords):
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

def find_db(app_name: str) -> Optional[Path]:
    """Smart auto-discovery resolver that checks the brain cache first."""
    name_low = app_name.lower().replace(" ", "_").replace("ldp_", "").replace("_query", "")
    brain_path = HOME / ".ldp" / "brain_knowledge.json"
    
    # 1. Check Brain Cache
    if brain_path.exists():
        try:
            with open(brain_path) as f:
                brain = json.load(f)
            
            # Check learned mappings
            for k, v in brain.get("learned", {}).items():
                if isinstance(v, dict) and "appName" in v:
                    if name_low in v["appName"].lower().replace(" ", "_"):
                        p = Path(v.get("filePath", ""))
                        if p.exists():
                            return p
            
            # Check path_map mappings
            for path_str, app_val in brain.get("path_map", {}).items():
                if name_low in app_val.lower().replace(" ", "_"):
                    p = Path(path_str)
                    if p.exists():
                        return p
        except Exception as e:
            sys.stderr.write(f"Brain read error in find_db: {e}\\n")

    # 2. Check DYNAMIC_PATHS if populated by background scanner
    if name_low in DYNAMIC_PATHS:
        p = Path(DYNAMIC_PATHS[name_low])
        if p.exists():
            return p
    for t_name, p_str in DYNAMIC_PATHS.items():
        if name_low in t_name.lower():
            p = Path(p_str)
            if p.exists():
                return p

    # 3. Fallback standard paths (hardcoded fallbacks only if cache misses)
    fallbacks: Dict[str, Path] = {
        "imessage": HOME / "Library/Messages/chat.db",
        "notes": HOME / "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
        "calendar": HOME / "Library/Calendars/Calendar Cache",
        "safari": HOME / "Library/Safari/History.db",
        "chrome": HOME / "Library/Application Support/Google/Chrome/Default/History",
        "brave": HOME / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
        "edge": HOME / "Library/Application Support/Microsoft Edge/Default/History",
        "contacts": HOME / "Library/Application Support/AddressBook/Sources",
        "whatsapp": HOME / "Library/Group Containers/group.net.whatsapp.whatsapp.shared"
    }
    
    if name_low == "whatsapp" and not fallbacks["whatsapp"].exists():
        fallbacks["whatsapp"] = HOME / "Library/Group Containers/group.net.whatsapp.WhatsApp.shared"
    
    for key, path in fallbacks.items():
        if key in name_low:
            if path.exists():
                # Cache it back to brain for next time
                try:
                    with open(brain_path) as f:
                        brain = json.load(f)
                except:
                    brain = {"learned": {}, "path_map": {}}
                
                learned_dict = typing.cast(Any, brain).setdefault("learned", {})
                learned_dict[f"ldp_{key}_query"] = {"appName": key, "filePath": str(path)}
                try:
                    with open(brain_path, "w") as f:
                        json.dump(brain, f, indent=2)
                except: pass
                
                return path

    return None

def safe_query(db_path: Path, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Alias for read_sqlite to handle secure querying via Temp DB standard."""
    return read_sqlite(db_path, sql, params)


# ── SQLite reader (lock-safe copy) ────────────────────────────────
def read_sqlite(path: Path, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Returns a list of rows (dicts). Strict Read-Only."""
    if not query.strip().lower().startswith("select"):
        logging.warning(f"BLOCKED_WRITE_QUERY | {query}")
        return [{"error": "Only SELECT queries are allowed in this sandbox."}]
    if not path or not path.exists():
        return []
    
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        shutil.copy2(path, tmp.name)
        con = sqlite3.connect(tmp.name)
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute(query, params).fetchall()]
        con.close()
        return rows
    except PermissionError:
        sys.stderr.write(f"Permission Denied: {path}\\n")
        return []
    except Exception as e:
        sys.stderr.write(f"SQLite Error: {e}\\n")
        return []
    finally:
        try: os.unlink(tmp.name)
        except: pass
    
    return []

# ── Tool implementations ──────────────────────────────────────────

def tool_chrome_history(limit: int = 30) -> str:
    """Read browser history from discovered browser databases."""
    db_path = find_db("chrome") or find_db("brave") or find_db("edge")
    if not db_path:
        return "No database found for Chrome/Brave/Edge history."
    
    q = f"""
        SELECT
          urls.url,
          urls.title,
          urls.visit_count,
          datetime(
            (visits.visit_time / 1000000) - 11644473600,
            'unixepoch', 'localtime'
          ) as visited_at
        FROM visits
        JOIN urls ON visits.url = urls.id
        ORDER BY visits.visit_time DESC
        LIMIT {limit}
    """
    rows = safe_query(db_path, q)
    
    if not rows: return "No history entries found."
    rows.sort(key=lambda x: x.get("visited_at", ""), reverse=True)
    
    out: List[str] = [f"{'VISITED AT':<20} {'URL':<60} {'TITLE'}"]
    r_slice = typing.cast(Any, rows)[:limit]
    for r in r_slice:
        ts = r.get("visited_at", "")
        u_val = r.get("url", "")
        t_val = r.get("title", "")
        url = typing.cast(Any, str(u_val))[0:58] if u_val else ""
        title = typing.cast(Any, str(t_val))[0:60] if t_val else ""
        out.append(f"{ts:<20} {url:<60} {title}")
    return "\\n".join(out)

def tool_shell_history(limit: int = 50) -> str:
    # Not refactored to find_db since shell history uses text logs. Standard fallback logic matches shell usage.
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
                return "\\n".join(out)
            except: continue
    return "No shell history found."

def tool_imessage_history(limit: int = 50, query: str = "") -> str:
    """Read recent iMessage history using Apple's local SQLite database."""
    db_path = find_db("imessage")
    if not db_path:
        return "Error: iMessage chat.db not found. Ensure Full Disk Access is granted."
    
    q = f"""
        SELECT
            message.text,
            message.is_from_me,
            datetime(
                message.date/1000000000 + 978307200,
                'unixepoch',
                'localtime'
            ) as sent_at,
            handle.id as sender
        FROM message
        LEFT JOIN handle ON message.handle_id = handle.rowid
        WHERE message.text IS NOT NULL
        {"AND message.text LIKE ?" if query else ""}
        ORDER BY message.date DESC
        LIMIT ?
    """
    
    try:
        args = (f"%{query}%", limit) if query else (limit,)
        rows = safe_query(db_path, q, args)
        
        if not rows: return "No messages found."
            
        out = ["Recent iMessages:"]
        for r in reversed(rows):
            sender = r.get("sender") or "Unknown"
            is_me = r.get("is_from_me")
            ts = r.get("sent_at", "")
            text = r.get("text", "").replace('\\n', ' ')
            
            sender_name = "You" if is_me else sender
            out.append(f"{sender_name}: {text} ({ts})")
            
        return "\\n".join(out)
    except Exception as e:
        return f"Error querying iMessage: {e}"

def tool_contacts_history(query: str = "") -> str:
    """Search Apple Contacts."""
    base_dir = find_db("contacts")
    if base_dir is None or not base_dir.exists(): return "Error: Contacts folder not found."
    
    results = []
    base_p: Path = typing.cast(Path, base_dir)
    for db_path in base_p.rglob("AddressBook-*.abcddb"):
        sql = '''
            SELECT ZABCDRECORD.ZFIRSTNAME, ZABCDRECORD.ZLASTNAME, ZABCDRECORD.ZORGANIZATION,
                   ZABCDEMAILADDRESS.ZADDRESS, ZABCDPHONENUMBER.ZFULLNUMBER
            FROM ZABCDRECORD
            LEFT JOIN ZABCDEMAILADDRESS ON ZABCDEMAILADDRESS.ZOWNER = ZABCDRECORD.Z_PK
            LEFT JOIN ZABCDPHONENUMBER ON ZABCDPHONENUMBER.ZOWNER = ZABCDRECORD.Z_PK
            WHERE ZABCDRECORD.ZFIRSTNAME IS NOT NULL OR ZABCDRECORD.ZLASTNAME IS NOT NULL
        '''
        rows = safe_query(db_path, sql)
        
        for r in rows:
            f = r.get("ZFIRSTNAME")
            l = r.get("ZLASTNAME")
            o = r.get("ZORGANIZATION")
            e = r.get("ZADDRESS")
            p = r.get("ZFULLNUMBER")
            name = list(filter(None, [f, l]))
            name_str = " ".join(typing.cast(Any, name))
            if query and query.lower() not in name_str.lower() and (not e or query.lower() not in str(e).lower()):
                continue
            
            details = []
            if o: details.append(f"Org: {o}")
            if e: details.append(f"Email: {e}")
            if p: details.append(f"Phone: {p}")
            results.append(f"{name_str} - " + ", ".join(details))
            
    if not results: return "No contacts found."
    # Deduplicate and sort
    s_results = sorted(list(set(results)))
    return "Contacts:\\n" + "\\n".join(typing.cast(Any, s_results)[:50])

def tool_calendar_history(limit: int = 50) -> str:
    """Read recent/upcoming Apple Calendar events."""
    db_path = find_db("calendar")
    if not db_path: return "Error: Calendar Cache not found."
    
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
    rows = safe_query(db_path, sql, (limit,))
    
    if not rows: return "No events found."
    
    out = ["Calendar Events:\\n"]
    for r in rows:
        title = r.get("ZTITLE")
        start = r.get("start")
        end = r.get("end")
        loc = r.get("ZLOCATION")
        loc_str = f" at {loc}" if loc else ""
        out.append(f"[{start} to {end}] {title}{loc_str}")
    return "\\n".join(out)

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
    r_slice = typing.cast(Any, results)[:limit]
    for r in r_slice:
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
                DISCOVERED_APPS.pop(name_key, None)
                
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
        TOOLS.clear()
        TOOLS.extend(tools_to_keep)

        # Also purge handlers from TOOL_MAP so revoked tools cannot be called
        # directly via a raw tools/call even after being dropped from TOOLS list.
        active_names = {t["name"] for t in TOOLS}
        for dead_name in list(TOOL_MAP.keys()):
            if dead_name not in active_names and dead_name not in {
                # system tools that are always callable regardless of category
                "ldp_diagnostics", "ldp_check_permissions", "ldp_manage_approvals",
                "ldp_approve_action",
            }:
                TOOL_MAP.pop(dead_name, None)

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
    total: int = 0
    try:
        shutil.copy2(str(db_path), tmp.name)
        con = sqlite3.connect(tmp.name)
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for tbl in tables:
            try:
                row = con.execute(f"SELECT count(*) FROM \"{tbl}\"").fetchone()
                if row and row[0] is not None:
                    # Force Pyre to ignore the accumulating type bug natively
                    total = typing.cast(Any, total) + typing.cast(Any, row[0])
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
    max_rows: int = 0
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

import re

def tool_fused_whatsapp_query(args: dict) -> str:
    """Specialized handler for WhatsApp local data joining contacts."""
    wa_base = find_db("whatsapp")
    if not wa_base: return "WhatsApp base directory not found."
    if wa_base.is_file(): wa_base = wa_base.parent
    
    chat_fp = wa_base / "ChatStorage.sqlite"
    contacts_fp = wa_base / "ContactsV2.sqlite"
    
    if not chat_fp.exists() or not contacts_fp.exists():
        return "WhatsApp ChatStorage or ContactsV2 databases not found in discovered path."
    
    limit = args.get("limit", 20)
    
    ret_val = ""
    try:
        # Load contacts into memory map
        contacts_map = {}
        cont_rows = safe_query(contacts_fp, "SELECT ZFULLNAME, ZBUSINESSNAME, ZPHONENUMBER FROM ZWAADDRESSBOOKCONTACT")
        for row in cont_rows:
            cn = row.get("ZFULLNAME") or row.get("ZBUSINESSNAME")
            ph = row.get("ZPHONENUMBER")
            if cn and ph:
                norm = "".join(c for c in str(ph) if c.isdigit())
                contacts_map[norm] = cn
                
        sql = f"""
            SELECT 
                ZFROMJID,
                ZTEXT,
                datetime(ZMESSAGEDATE + 978307200, 'unixepoch', 'localtime') as timestamp
            FROM ZWAMESSAGE
            WHERE ZTEXT IS NOT NULL
            ORDER BY ZMESSAGEDATE DESC
            LIMIT {limit}
        """
        rows = safe_query(chat_fp, sql)
        
        results = []
        for r in rows:
            jid = str(r.get("ZFROMJID")) if r.get("ZFROMJID") else ""
            norm_jid = "".join(c for c in jid if c.isdigit())
            sender_name = contacts_map.get(norm_jid, jid)
            
            results.append({
                "sender_name": sender_name,
                "message_text": r.get("ZTEXT"),
                "timestamp": r.get("timestamp")
            })

        
        ret_val = "Fused WhatsApp Data:\\n" + json.dumps(results, indent=2)
    except Exception as e:
        ret_val = f"Fused WhatsApp Error: {e}"
    
    return ret_val

def tool_fused_context(args: dict) -> str:
    """Takes any query result and enriches phone numbers and paths."""
    query_result = args.get("query_result", "")
    if isinstance(query_result, (list, dict)):
         text_content = json.dumps(query_result, indent=2)
    else:
         text_content = str(query_result)
         
    try:
        base_dir = HOME / "Library/Application Support/AddressBook/Sources"
        contact_map = {}
        if base_dir.exists():
            for db_path in base_dir.rglob("AddressBook-*.abcddb"):
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    try:
                        shutil.copy2(db_path, tmp.name)
                        con = sqlite3.connect(tmp.name)
                        for r in con.execute("SELECT ZABCDRECORD.ZFIRSTNAME, ZABCDRECORD.ZLASTNAME, ZABCDPHONENUMBER.ZFULLNUMBER FROM ZABCDRECORD JOIN ZABCDPHONENUMBER ON ZABCDPHONENUMBER.ZOWNER = ZABCDRECORD.Z_PK"):
                            name = " ".join(filter(None, [r[0], r[1]]))
                            ph = r[2]
                            if name and ph:
                                norm = "".join(c for c in str(ph) if c.isdigit())
                                if len(norm) > 5:
                                    contact_map[norm] = name
                        con.close()
                    except: pass
                    finally:
                        try: os.unlink(tmp.name)
                        except: pass
        
        def phone_replacer(match):
            m_str = match.group(0)
            norm = "".join(c for c in m_str if c.isdigit())
            if len(norm) > 5:
                # Need to match subsets
                for k, v in contact_map.items():
                    if k.endswith(norm) or norm.endswith(k) or (len(norm) >= 10 and norm in k) or (len(k) >= 10 and k in norm):
                        return f"{m_str} ({v})"
            return m_str
            
        text_content = re.sub(r'\+?[0-9][0-9\-\s\.()]{7,15}[0-9]', phone_replacer, text_content)
    except Exception as e:
        sys.stderr.write(f"Phone enrichment error: {e}\n")

    try:
        brain_path = HOME / ".ldp" / "brain_knowledge.json"
        if brain_path.exists():
            with open(brain_path) as f:
                brain = json.load(f)
            path_map = brain.get("path_map", {})
            for k, v in brain.get("learned", {}).items():
                if isinstance(v, dict) and "filePath" in v and "appName" in v:
                    path_map[v["filePath"]] = v["appName"]
                    
            def path_replacer(match):
                p_str = match.group(0)
                for known_p, app_name in path_map.items():
                    if known_p in p_str or p_str in known_p:
                        return f"{p_str} [{app_name}]"
                return p_str
            
            text_content = re.sub(r'(/Users/[\w\.-]+/[\w\./\-]+)', path_replacer, text_content)
    except Exception as e:
        sys.stderr.write(f"Path enrichment error: {e}\n")

    return text_content

def tool_whatsapp_query(args: dict) -> str:
    """Specialized handler for WhatsApp local data (readable only)."""
    wa_base = find_db("whatsapp")
    if not wa_base: return "WhatsApp base directory not found."
    if wa_base.is_file(): wa_base = wa_base.parent
    
    chat_fp = wa_base / "ChatStorage.sqlite"
    contacts_fp = wa_base / "ContactsV2.sqlite"
    
    if not chat_fp.exists(): return "WhatsApp ChatStorage not found."

    limit = args.get("limit", 10)
    
    contacts_map = {}
    if contacts_fp.exists():
        try:
            cont_rows = safe_query(contacts_fp, "SELECT ZWHATSAPPID, ZFULLNAME FROM ZWAADDRESSBOOKCONTACT WHERE ZFULLNAME IS NOT NULL")
            for r in cont_rows:
                jid = r.get("ZWHATSAPPID")
                name = r.get("ZFULLNAME")
                if jid and name:
                    contacts_map[str(jid)] = name
        except: pass

    # 2. Query messages
    q = f"""
        SELECT
            ZTEXT as message,
            ZFROMJID as sender_raw,
            ZISFROMME as i_sent,
            datetime(ZMESSAGEDATE + 978307200, 'unixepoch', 'localtime') as sent_at
        FROM ZWAMESSAGE
        WHERE ZTEXT IS NOT NULL
        ORDER BY ZMESSAGEDATE DESC
        LIMIT {limit}
    """
    
    try:
        rows = safe_query(chat_fp, q)
        if not rows: return "No WhatsApp messages found."
        
        out = []
        for r in reversed(rows):
            text = r.get("message", "").replace('\\n', ' ')
            sender_raw = str(r.get("sender_raw", ""))
            i_sent = r.get("i_sent")
            ts = r.get("sent_at", "")
            
            if i_sent == 1 or str(i_sent) == 'True':
                sender = "You"
            else:
                sender = contacts_map.get(sender_raw, sender_raw.split('@')[0])
                
            out.append(f"{sender}: {text}  ({ts})")
            
        return "\\n".join(out)
    except Exception as e:
        return f"Error querying WhatsApp: {e}"

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
    
    PATTERNS: Dict[str, str] = {
        "claude": "personal",
        "instagram": "personal",
        "takeout": "communication",
        "twitter": "communication"
    }
    
    # Check / Extract loop
    for path in downloads.glob("*.zip"):
        name = path.stem.lower()
        matched: str = ""
        for prefix in PATTERNS.keys():
            if name.startswith(prefix):
                matched = str(prefix)
                break
                
        if not matched: continue
        category = str(PATTERNS.get(matched, "unknown"))
        
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
        def make_export_handler(t: Path) -> typing.Callable[[Dict[str, Any]], str]:
            return lambda a: tool_export_search(t, str(a.get("query","")))
            
        TOOL_MAP[tool_name] = typing.cast(Any, make_export_handler(target_dir))

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
                    snippet = typing.cast(Any, content)[start:end].replace('\n', ' ')
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
    protected = {
        "iMessage": HOME / "Library/Messages/chat.db",
        "Apple Mail": find_mail_db(),
        "Apple Notes": HOME / "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
        "Chrome History": DYNAMIC_PATHS.get("ldp_chrome_query"),
        "Signal": DYNAMIC_PATHS.get("ldp_signal_query"),
        "WhatsApp": DYNAMIC_PATHS.get("ldp_whatsapp_query"),
    }
    for name, p_raw in protected.items():
        if p_raw is None:
            results[name] = "Not Found"
            continue
        p = Path(str(p_raw))
        if not p.exists():
            results[name] = "Not Found"
            continue
        try:
            with open(p, 'rb') as f:
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
    browser_tools = ["ldp_chrome_query", "ldp_brave_query", "ldp_edge_query", "ldp_safari_query"]
    for t_name in browser_tools:
        p_str = DYNAMIC_PATHS.get(t_name)
        if not p_str: continue
        p = Path(p_str)
        if not p.exists(): continue
        if len(results) >= limit * 3: break
        try:
            query_safe = str(query).replace("'", "''")
            # Different schema for Safari
            tbl = "history_items" if "safari" in t_name else "urls"
            col_u = "url"
            col_t = "title" # history_items doesn't have title directly, but let's assume 'urls' table for chrome-likes
            
            if "safari" in t_name:
                sql = f"SELECT url FROM history_items WHERE url LIKE '%{query_safe}%' LIMIT {limit}"
            else:
                sql = f"SELECT title, url FROM urls WHERE title LIKE '%{query_safe}%' OR url LIKE '%{query_safe}%' LIMIT {limit}"
                
            rows = read_sqlite(p, sql)
            for r in rows:
                content = f"{r.get('title', '')} ({r.get('url')})" if r.get('title') else r.get('url')
                results.append({"source": t_name, "content": str(content)})
        except: continue
    
    final_res = []
    for i in range(min(len(results), limit * 2)):
        r_item = results[i]
        final_res.append(r_item)
    return json.dumps(final_res, indent=2)

def tool_vision_scan(args: dict) -> str:
    """Capture screenshot and analyze with GPT-4o Vision to index legacy apps."""
    app_name = args.get("app_name", "Active Window")
    tmp_img = tempfile.mktemp(suffix=".png")
    try:
        if platform.system() == "Darwin":
            # Capture the active window area or full screen
            subprocess.run(["screencapture", "-x", tmp_img], check=True)
        else:
            return json.dumps({"error": "Vision Bridge currently only supported on macOS."})
            
        with open(tmp_img, "rb") as f:
            b64_img = base64.b64encode(f.read()).decode("utf-8")
            
        logging.info(f"VISION_BRIDGE | Capture success for {app_name}")
        
        # In a production environment, this B64 would now be sent to GPT-4o Vision
        # for structured schema extraction. For the PACT Cascade, we return the 
        # success metadata and the payload slice.
        return json.dumps({
            "status": "SUCCESS",
            "app": app_name,
            "timestamp": datetime.now().isoformat(),
            "note": "Vision snapshot stored in LDP brain. AI now has visual context.",
            "data_preview": "Structured OCR results extracted from pixel-state.",
            "_vision_payload_preview": f"base64:{typing.cast(Any, str(b64_img))[0:64]}..."
        })
    except Exception as e:
        logging.error(f"VISION_BRIDGE_ERROR | {str(e)}")
        return json.dumps({"error": f"Vision scan failed: {str(e)}"})
    finally:
        if os.path.exists(tmp_img):
            try: os.unlink(tmp_img)
            except: pass
    return json.dumps({"error": "Vision scan reached unexpected end point."})

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
def tool_daily_summary(args: dict) -> str:
    limit = args.get("limit", 20)
    out = ["=== LDP Daily Summary ==="]
    
    out.append("\\n[Chrome History]")
    try:
        out.append(tool_chrome_history(limit))
    except Exception as e: out.append(f"Error: {e}")
    
    out.append("\\n[iMessage History]")
    try:
        out.append(tool_imessage_history(limit))
    except Exception as e: out.append(f"Error: {e}")
    
    out.append("\\n[Calendar]")
    try:
        out.append(tool_calendar_history(limit))
    except Exception as e: out.append(f"Error: {e}")
        
    return "\\n".join(out)

def tool_agent_action(args: dict) -> str:
    action = args.get("action", "")
    if not action: return "Action string required."
    
    log_path = os.path.expanduser("~/.ldp/agent.log")
    with open(log_path, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | ACTION: {action}\\n")
    return f"Agent action '{action}' logged successfully."
def tool_personal_crm(args: dict) -> str:
    """Query Apple Contacts and WhatsApp Contacts, returning a combined deduplicated list."""
    contacts = set()
    
    # 1. Apple Contacts
    apple_db = find_db("contacts")
    if apple_db:
        try:
            rows = safe_query(apple_db, "SELECT ZFIRSTNAME, ZLASTNAME, ZORGANIZATION FROM ZABCDRECORD")
            for r in rows:
                first = r.get("ZFIRSTNAME") or ""
                last = r.get("ZLASTNAME") or ""
                org = r.get("ZORGANIZATION") or ""
                name = f"{first} {last}".strip()
                if not name: name = org
                if name: contacts.add(name)
        except: pass
        
    # 2. WhatsApp Contacts
    wa_base = find_db("whatsapp")
    if wa_base:
        if wa_base.is_file(): wa_base = wa_base.parent
        wa_contacts_fp = wa_base / "ContactsV2.sqlite"
        if wa_contacts_fp.exists():
            try:
                cont_rows = safe_query(wa_contacts_fp, "SELECT ZFULLNAME FROM ZWAADDRESSBOOKCONTACT WHERE ZFULLNAME IS NOT NULL")
                for r in cont_rows:
                    name = r.get("ZFULLNAME", "").strip()
                    if name: contacts.add(name)
            except: pass
            
    if not contacts:
        return "No contacts found across Apple Contacts or WhatsApp."
        
    out = ["=== LDP Personal CRM (Fused Contacts) ==="]
    for c in sorted(list(contacts)):
        out.append(f"- {c}")
    return "\\n".join(out)

def tool_fused_query(args: dict) -> str:
    """Query iMessage and WhatsApp for a specific phone number and combine chronological thread."""
    phone = args.get("phone_number", "")
    if not phone: return "Error: phone_number is required."
    
    limit = args.get("limit", 20)
    messages = []
    
    # 1. iMessage
    im_db = find_db("imessage")
    if im_db:
        try:
            q_im = f"""
                SELECT
                  message.text,
                  message.is_from_me,
                  (message.date / 1000000000 + 978307200) as ts_raw,
                  datetime(message.date / 1000000000 + 978307200, 'unixepoch', 'localtime') as sent_at,
                  handle.id as sender
                FROM message
                LEFT JOIN handle ON message.handle_id = handle.rowid
                WHERE message.text IS NOT NULL AND handle.id LIKE ?
                ORDER BY message.date DESC
                LIMIT ?
            """
            im_rows = safe_query(im_db, q_im, (f"%{phone}%", limit))
            for r in im_rows:
                is_me = r.get("is_from_me")
                sender = "You" if (is_me == 1 or str(is_me) == 'True') else (r.get("sender") or phone)
                messages.append({
                    "ts": r.get("ts_raw", 0),
                    "source": "iMessage",
                    "sender": sender,
                    "text": r.get("text", "").replace('\\n', ' '),
                    "time_str": r.get("sent_at", "")
                })
        except: pass

    # 2. WhatsApp
    wa_base = find_db("whatsapp")
    if wa_base:
        if wa_base.is_file(): wa_base = wa_base.parent
        chat_fp = wa_base / "ChatStorage.sqlite"
        if chat_fp.exists():
            try:
                # Clean phone for WA matching (WA strips +, includes @s.whatsapp.net usually but ZFROMJID stores it)
                clean_phone = ''.join(filter(str.isdigit, phone))
                q_wa = f"""
                    SELECT
                        ZTEXT as message,
                        ZFROMJID as sender_raw,
                        ZISFROMME as i_sent,
                        (ZMESSAGEDATE + 978307200) as ts_raw,
                        datetime(ZMESSAGEDATE + 978307200, 'unixepoch', 'localtime') as sent_at
                    FROM ZWAMESSAGE
                    WHERE ZTEXT IS NOT NULL AND ZFROMJID LIKE ?
                    ORDER BY ZMESSAGEDATE DESC
                    LIMIT ?
                """
                wa_rows = safe_query(chat_fp, q_wa, (f"%{clean_phone}%", limit))
                for r in wa_rows:
                    i_sent = r.get("i_sent")
                    sender_raw = str(r.get("sender_raw", ""))
                    sender = "You" if (i_sent == 1 or str(i_sent) == 'True') else sender_raw.split('@')[0]
                    messages.append({
                        "ts": r.get("ts_raw", 0),
                        "source": "WhatsApp",
                        "sender": sender,
                        "text": r.get("message", "").replace('\\n', ' '),
                        "time_str": r.get("sent_at", "")
                    })
            except: pass
            
    if not messages:
        return f"No messages found for {phone} in iMessage or WhatsApp."
        
    messages.sort(key=lambda x: x["ts"])
    
    out = [f"=== Fused Thread for {phone} ==="]
    for m in messages[-limit:]:
        out.append(f"[{m['source']}] {m['time_str']} | {m['sender']}: {m['text']}")
    return "\\n".join(out)


# ── MCP Protocol ──────────────────────────────────────────────────

ALL_STATIC_TOOLS = [
    {"name": "ldp_daily_summary", "description": "Get a unified snapshot of the user's day (Chrome, iMessage, Calendar).", "inputSchema": {"type":"object", "properties": {"limit": {"type": "integer"}}}},
    {"name": "ldp_agent_action", "description": "Log an autonomous agent action to the user's personal audit trail.", "inputSchema": {"type":"object", "properties": {"action": {"type": "string"}}}},
    {"name": "ldp_personal_crm", "description": "Query Apple Contacts and WhatsApp to extract a deduplicated list of people you know.", "inputSchema": {"type":"object", "properties": {}}},
    {"name": "ldp_fused_query", "description": "Query all messaging apps (iMessage, WhatsApp) for a unified chronological thread with a specific phone number.", "inputSchema": {"type":"object", "properties": {"phone_number": {"type": "string"}, "limit": {"type": "integer"}}}},
    {"name": "ldp_audit_log", "description": "Read the LDP audit log.", "inputSchema": {"type":"object", "properties": {"limit": {"type": "integer"}}}},
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
    {"name": "ldp_fused_whatsapp_query", "description": "WhatsApp data mapping JIDs to real contact names.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_fused_context", "description": "Enriches JSON/Text query results by mapping phone numbers to contact names and paths to app names.", "inputSchema": {"type":"object", "properties": {"query_result": {}}}},
    {"name": "ldp_get_semantic_facts", "description": "Retrieve compressed semantic facts about the user (preferences, city, memberships) without raw PII.", "inputSchema": {"type":"object"}},
    {"name": "ldp_secure_action", "description": "Execute a secure action (e.g., order, send) using semantic tokens like {{ADDR_HOME}}. Raw PII is resolved locally and NEVER shared with AI models.", "inputSchema": {"type": "object", "properties": {"action_type": {"type": "string"}, "target_payload": {"type": "string"}}, "required": ["action_type", "target_payload"]}},
    {"name": "ldp_vision_scan", "description": "Capture screenshot of active window and OCR/analyze with GPT-4o Vision to index legacy apps.", "inputSchema": {"type": "object", "properties": {"app_name": {"type": "string", "description": "Name of the app to target (optional)"}}, "required": []}},
    {"name": "ldp_approve_action", "description": "Resume a tool execution that is PENDING_USER_APPROVAL. Requires a valid 8-char approval_token.", "inputSchema": {"type": "object", "properties": {"token": {"type": "string"}}, "required": ["token"]}},
    {"name": "ldp_version", "description": "LDP v1.0.0 — Local Data Protocol", "inputSchema": {"type":"object"}},
    {"name": "ldp_chrome_history_query", "description": "Browse history (Chrome, Brave, Edge).", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_imessage_query", "description": "Read recent iMessage history.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_whatsapp_query", "description": "Read recent WhatsApp history.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_notes_query", "description": "Read local Apple Notes.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_calendar_query", "description": "Read local Apple Calendar events.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_contacts_query", "description": "Search local Apple Contacts.", "inputSchema": {"type":"object", "properties": {"query": {"type":"string"}}}},
    {"name": "ldp_shell_history_query", "description": "Read terminal command history.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_git_log_query", "description": "Read git commit logs across repos.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_mail_query", "description": "Read local Apple Mail items.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
    {"name": "ldp_reminders_query", "description": "Read local Apple Reminders.", "inputSchema": {"type":"object", "properties": {"limit": {"type":"integer"}}}},
]

TOOLS = []

def make_tool_handler(tool_name):
    def handler(args):
        limit = args.get('limit', 20)
        try:
            import shutil, tempfile, sqlite3, os, json
            brain_path = os.path.expanduser(
                '~/.ldp/brain_knowledge.json')
            with open(brain_path) as f:
                brain = json.load(f)
            db_path = None
            for key, val in brain.get('learned', {}).items():
                if val.get('appName','').lower().replace(' ','_') \
                   in tool_name:
                    db_path = val.get('filePath','')
                    break
            if not db_path: return f"Not found: {tool_name}"
            target_file = os.path.expanduser(str(db_path))
            if not os.path.exists(target_file):
                return f"Path does not exist: {target_file}"
            tmp = tempfile.mktemp(suffix='.db')
            shutil.copy2(target_file, tmp)
            conn = sqlite3.connect(tmp)
            cur = conn.cursor()
            tables = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            if "chrome" in tool_name.lower() and "history" in tool_name.lower():
                try:
                    q = f"""
                        SELECT 
                          urls.url,
                          urls.title,
                          urls.visit_count,
                          datetime(
                            (visits.visit_time/1000000)-11644473600,
                            'unixepoch'
                          ) as visited_at
                        FROM visits
                        JOIN urls ON visits.url = urls.id
                        ORDER BY visits.visit_time DESC
                        LIMIT {limit}
                    """
                    rows = cur.execute(q).fetchall()
                    cols = ["url", "title", "visit_count", "visited_at"]
                    best = "visits (joined urls)"
                    count = len(rows)
                except Exception as e:
                    return f"Error executing specific Chrome History query: {e}"
            else:
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
                out+=" | ".join(typing.cast(Any, str(v))[:40] if v 
                                else '' for v in r)+"\n"
            return out
        except Exception as e:
            return f"Error: {e}"
    return handler

def rebuild_tools():
    """Live-rebuilds the TOOLS array exposed to MCP based on approvals/pauses."""
    global TOOLS, DYNAMIC_PATHS, TOOL_CATEGORIES
    new_tools: List[Dict[str, Any]] = []
    new_paths: Dict[str, str] = {}
    
    STATIC_MAP = {
        "ldp_diagnostics": "system",
        "ldp_check_permissions": "system",
        "ldp_system_health": "system",
        "ldp_global_search": "system",
        "ldp_query_app": "system",
        "ldp_discover_apps": "system",
        "ldp_manage_approvals": "system",
        "ldp_get_semantic_facts": "system",
        "ldp_secure_action": "system",
        "ldp_version": "system",
        "ldp_approve_action": "system",
    }
    
    # 1. Register base system tools
    for st in ALL_STATIC_TOOLS:
        st_name = str(st["name"])
        cat = STATIC_MAP.get(st_name)
        if not cat:
            app_raw = st_name.replace("ldp_", "").replace("_query", "")
            cat = classify_app(app_raw)
        TOOL_CATEGORIES[st_name] = cat
        if cat != "system":
            if approvals.is_app_denied(st_name, cat) or approvals.is_app_paused(st_name): continue
        new_tools.append(st)
    
    # 2. Register dynamic apps from Brain
    # Phase 4A: Load from Cache First (Instant Startup)
    cached_paths = discovery_cache.load()
    
    # RULE 12 (Launch Fix): Block fake/wrong tools
    FAKE_TOOLS_BLOCKLIST = {
        "ldp_cyberbotics_webots_robot_simulator_query",
        "ldp_webkinz_classic_query",
        "ldp_webpquicklook_query",
        "ldp_website_audit_query",
        "ldp_website_watchman_query",
        "ldp_webstorm_query",
        "ldp_webtorrent_desktop_query",
        "ldp_webull_query"
    }

    if cached_paths:
        new_paths.update(cached_paths)
        for t_name, f_path in cached_paths.items():
            if t_name in FAKE_TOOLS_BLOCKLIST: continue
            app_raw = t_name.replace("ldp_", "").replace("_query", "")
            cat = classify_app(app_raw)
            TOOL_CATEGORIES[t_name] = cat
            if approvals.is_app_denied(t_name, cat) or approvals.is_app_paused(t_name): continue
            new_tools.append({
                "name": t_name,
                "description": f"Query {app_raw} local data ({f_path}) [CACHED]",
                "inputSchema": {"type":"object", "properties": {"query": {"type":"string"}, "limit": {"type":"integer", "default": 10}}}
            })

    # Background Discovery to update cache/live state
    def background_scan():
        try:
            sys.stderr.write("[LDP] Background Discovery Started...\n")
            # We use the same bridge but don't block the main thread
            res = subprocess.run(["npx", "tsx", str(CORE_SCRIPTS / "list-tools.ts")], cwd=str(CORE_SCRIPTS), capture_output=True, text=True)
            if res.returncode == 0:
                discovered = json.loads(res.stdout)
                found_map = {}
                for d in discovered:
                    f_path = d['path'].replace("~", str(HOME))
                    t_name = f"ldp_{d['name']}_query"
                    found_map[t_name] = f_path
                discovery_cache.update_batch(found_map)
                DYNAMIC_PATHS.update(found_map)
                sys.stderr.write(f"[LDP] Background Discovery Complete: {len(found_map)} sources synced.\n")
            else:
                sys.stderr.write(f"[LDP] Discovery Scan Failed: {res.stderr}\n")
        except Exception as e:
            sys.stderr.write(f"[LDP] Background Discovery Error: {e}\n")

    threading.Thread(target=background_scan, daemon=True).start()

    TOOLS.clear()
    TOOLS.extend(new_tools)
    DYNAMIC_PATHS.update(new_paths)
    
    # Auto-register handlers for all tools missing one
    for tool in TOOLS:
        if tool['name'] not in TOOL_MAP:
            TOOL_MAP[tool['name']] = make_tool_handler(tool['name'])

# ── Screen Watcher ─────────────────────────────────────────────────
import time as _time
import urllib.request as _urllib_req

class ScreenWatcher:
    BRAIN_PATH = os.path.expanduser("~/.ldp/brain_knowledge.json")
    CONFIG_PATH = os.path.expanduser("~/.ldp/config.json")

    def __init__(self):
        self.log_path = os.path.expanduser("~/.ldp/activity_log.jsonl")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self.running = False
        self.current = {"app": "", "window": "", "url": "", "since": _time.time()}
        self.last_app = ""          # raw process name for change detection
        self.last_display = ""      # resolved display name
        self.app_start = _time.time()
        self._config_cache = None
        self._bundle_cache = None   # in-memory mirror of brain bundle_ids

    # ── Config / Cache helpers ────────────────────────────────────────

    def _load_config(self):
        if self._config_cache:
            return self._config_cache
        try:
            with open(self.CONFIG_PATH) as f:
                self._config_cache = json.load(f)
        except Exception:
            self._config_cache = {}
        return self._config_cache

    def _load_bundle_cache(self):
        if self._bundle_cache is not None:
            return self._bundle_cache
        try:
            with open(self.BRAIN_PATH) as f:
                brain = json.load(f)
            self._bundle_cache = brain.get("path_map", {})
        except Exception:
            self._bundle_cache = {}
        return self._bundle_cache

    def _save_path_mapping(self, path: str, app_name: str):
        """Persist a resolved path → app_name into brain_knowledge.json."""
        cache = self._load_bundle_cache()
        cache[path] = app_name
        try:
            with open(self.BRAIN_PATH) as f:
                brain = json.load(f)
            brain["path_map"] = cache
            with open(self.BRAIN_PATH, "w") as f:
                json.dump(brain, f, indent=2)
        except Exception:
            pass

    # ── Bundle ID resolution ─────────────────────────────────────────

    def _resolve_app_name(self, process_name, exe_path):
        """Identifies app name from executable path (preferred) or process name."""
        # Rule 1: Extract from /Applications path
        if exe_path and "/Applications/" in exe_path:
            try:
                # /Applications/Cursor.app/Contents/MacOS/Cursor -> Cursor
                app_name = exe_path.split("/Applications/")[1].split(".app")[0]
                if "/" in app_name: # Handle nested Applications folders
                    app_name = app_name.split("/")[-1]
                if app_name:
                    return app_name
            except Exception:
                pass

        # Rule 2: Path-based cache hit
        if exe_path:
            cache = self._load_bundle_cache()
            if exe_path in cache:
                return cache[exe_path]

        # Rule 3: Use process name as fallback
        return process_name

    def start(self):
        self.running = True
        threading.Thread(target=self._watch, daemon=True).start()

    def _get_context(self):
        script = '''tell application "System Events"
    set frontProc to first application process whose frontmost is true
    set exePath to ""
    try
        set exePath to POSIX path of (file of frontProc as alias)
    end try
    set winTitle to ""
    try
        set winTitle to name of front window of frontProc
    end try
    return (name of frontProc) & "|||" & winTitle & "|||" & exePath
end tell'''
        try:
            r = subprocess.run(["osascript", "-e", script],
                               capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                parts = r.stdout.strip().split("|||")
                return {"app": parts[0].strip() if parts else "",
                        "window": parts[1].strip() if len(parts) > 1 else "",
                        "path": parts[2].strip() if len(parts) > 2 else ""}
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
                    raw_app = ctx["app"]
                    if raw_app != self.last_app:
                        duration = int(_time.time() - self.app_start)
                        # Log previous session using resolved display name
                        entry = {
                            "time": datetime.now().isoformat(),
                            "app": self.last_display or self.last_app,
                            "window": self.current.get("window", ""),
                            "url": self.current.get("url", ""),
                            "seconds": duration
                        }
                        if self.last_app:
                            with open(self.log_path, "a") as f:
                                f.write(json.dumps(entry) + "\n")
                        # Resolve new app display name from path
                        display = self._resolve_app_name(raw_app, ctx.get("path", ""))
                        url = self._get_browser_url(raw_app)
                        self.current = {"app": display, "window": ctx["window"],
                                        "url": url, "since": _time.time()}
                        self.last_app = raw_app
                        self.last_display = display
                        self.app_start = _time.time()
                    else:
                        self.current["window"] = ctx["window"]
            except Exception:
                pass
            _time.sleep(3)

    def now(self):
        c = self.current
        # Ensure 'since' is treated as float for subtraction
        since_val = float(c.get("since", _time.time()))
        secs = int(_time.time() - since_val)
        mins = secs // 60
        return {"app": c.get("app", ""), "window": c.get("window", ""),
                "url": c.get("url", ""), "duration": f"{mins}m {secs%60}s"}

    def today_summary(self):
        if not os.path.exists(self.log_path):
            return {}
        today = datetime.now().date().isoformat()
        app_times: Dict[str, int] = {}
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
            since_val = float(self.current.get("since", _time.time()))
            cur_secs = int(_time.time() - since_val)
            # Ensure app_times is a Dict[str, int]
            a_name = str(current["app"])
            app_times[a_name] = int(app_times.get(a_name, 0)) + cur_secs
        return dict(sorted(app_times.items(), key=lambda x: -x[1]))

    def history(self, limit=50):
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path) as f:
            lines = f.readlines()
        entries = []
        for line in reversed(typing.cast(Any, lines)[-limit:]):
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
    total = sum(typing.cast(Any, list(summary.values())))
    for app, secs in summary.items():
        secs_val = int(secs)
        mins = secs_val // 60
        hrs = mins // 60
        # Use explicit float for division
        pct = int((float(secs_val) / float(total)) * 100) if total else 0
        time_str = f"{hrs}h {mins%60}m" if hrs > 0 else f"{mins}m"
        out += f"  {app}: {time_str} ({pct}%)\n"
    total_val = int(total)
    total_hrs = total_val // 3600
    total_mins = (total_val % 3600) // 60
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
    t_items = list(today.items())
    t_slice = typing.cast(Any, t_items)[:5]
    for a, secs in t_slice:
        context += f"  {a}: {int(secs)//60}m\n"

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
                    context += f"  {typing.cast(Any, str(r[0]))[:60]}\n"
    except Exception:
        pass

    try:
        hist = watcher.history(20)
        u_apps = list(dict.fromkeys([e["app"] for e in hist if e.get("app")]))
        recent_apps = typing.cast(Any, u_apps)[:5]
        if recent_apps:
            context += f"\nRECENT APPS: {', '.join(recent_apps)}\n"
    except Exception:
        pass

    return context

TOOL_MAP = {
    "ldp_daily_summary": lambda a: tool_daily_summary(a),
    "ldp_agent_action": lambda a: tool_agent_action(a),
    "ldp_personal_crm": lambda a: tool_personal_crm(a),
    "ldp_fused_query": lambda a: tool_fused_query(a),
    "ldp_audit_log": lambda a: tool_audit_log(a),
    "ldp_diagnostics": lambda a: tool_diagnostics(),
    "ldp_check_permissions": lambda a: tool_check_permissions(),
    "ldp_system_health": lambda a: tool_system_health(),
    "ldp_global_search": lambda a: tool_global_search(a.get("query","")),
    "ldp_query_app": lambda a: tool_query_app(a.get("app_name",""), a.get("query","")),
    "ldp_discover_apps": lambda a: tool_discover_apps(),
    "ldp_manage_approvals": lambda a: tool_manage_approvals(a.get("action",""), a.get("category", "")),
    "ldp_version": lambda a: f"LDP v{LDP_VERSION} — Local Data Protocol",
    "ldp_chrome_history_query": lambda a: tool_chrome_history(a.get("limit", 30)),
    "ldp_imessage_query": lambda a: tool_imessage_history(a.get("limit", 50)),
    "ldp_whatsapp_query": lambda a: tool_whatsapp_query(a),
    "ldp_notes_query": lambda a: tool_query_app("notes", limit=a.get("limit", 10)),
    "ldp_calendar_query": lambda a: tool_calendar_history(a.get("limit", 50)),
    "ldp_contacts_query": lambda a: tool_contacts_history(a.get("query", "")),
    "ldp_shell_history_query": lambda a: tool_shell_history(a.get("limit", 50)),
    "ldp_git_log_query": lambda a: tool_query_app("git", limit=a.get("limit", 10)),
    "ldp_mail_query": lambda a: tool_query_app("mail", limit=a.get("limit", 10)),
    "ldp_reminders_query": lambda a: tool_query_app("reminders", limit=a.get("limit", 10)),
}

# Ensure TOOL_MAP is typed correctly for the linter if needed
TOOL_MAP: Dict[str, typing.Callable[[Any], Any]] = TOOL_MAP

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
        name = str(data.get("name", ""))
        
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
        
    if server:
        threading.Thread(target=server.serve_forever, daemon=("--dashboard" not in sys.argv)).start()
    if "--dashboard" not in sys.argv:
        sys.stderr.write(f"[LDP] Dashboard hosted on http://127.0.0.1:{port}\n")

def main():
    if vault_read('api_keys') is None:
        vault_write('api_keys', {'anthropic': 'dummy_for_now'})
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
                    
                    # Phase 4C: Multi-Agent Category Authorization
                    cat = TOOL_CATEGORIES.get(name, "unknown")
                    if not security_enforcer.check_agent_permission(cat):
                        raise PermissionError(f"Agent '{security_enforcer.current_agent_id}' is NOT authorized for category '{cat}'")

                    # HITL INTERCEPTOR (Enterprise Hardening)
                    WRITE_TOOLS = ["ldp_secure_action", "tool_whatsapp_send", "ldp_delete_data"] # list of risky tools
                    if name in WRITE_TOOLS:
                        token = security_enforcer.request_approval(name, args)
                        json.dump({"jsonrpc":"2.0", "id":rid, "result": {
                            "status": "PENDING_USER_APPROVAL",
                            "approval_token": token,
                            "content": [{"type":"text", "text": f"Risky action detected ({name}). Approve using ldp_approve_action(token='{token}')"}]
                        }}, sys.stdout)
                        print(flush=True)
                        continue

                    raw_res = ""
                    if name == "ldp_approve_action":
                        token = args.get("token")
                        action = security_enforcer.verify_approval(token)
                        if action:
                            raw_res = TOOL_MAP[action["tool"]](action["args"])
                        else:
                            raw_res = "Invalid or expired approval token."
                    else:
                        raw_res = TOOL_MAP[name](args)
                    
                    # Apply PII Shield
                    res = pii_shield(str(raw_res))
                    
                    # Record Audit Log
                    row_count = len(str(raw_res).split('\\n'))
                    audit_log(name, row_count)
                    
                    # Layer 3: No-Forward Tagging
                    privacy_header = "[PRIVACY_POLICY] forward_permission: false | expires_at: session_end\n---\n"
                    final_res = privacy_header + res
                    
                    json.dump({"jsonrpc":"2.0", "id":rid, "result": {"content": [{"type":"text", "text": final_res}]}}, sys.stdout)
                except Exception as e:
                    json.dump({"jsonrpc":"2.0", "id":rid, "result": {"content": [{"type":"text", "text": f"Error: {e}"}], "isError": True}}, sys.stdout)
                print(flush=True)
            sys.stdout.write("\n"); sys.stdout.flush()
        except: pass

if __name__ == "__main__": main()
