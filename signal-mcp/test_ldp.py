"""
Quick test — run this FIRST to verify LDP works on your Mac
before connecting to Cursor.
"""
import sqlite3, shutil, os, tempfile
from pathlib import Path

HOME = Path.home()
print("\n=== LDP Quick Test ===\n")

# 1. Python version
import sys
print(f"Python:  {sys.version.split()[0]}  ✓")

# 2. Chrome / Brave
chrome = HOME / "Library/Application Support/Google/Chrome/Default/History"
brave  = HOME / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History"
browser_path = chrome if chrome.exists() else (brave if brave.exists() else None)

if browser_path:
    print(f"Browser: {browser_path.parts[-4]}  ✓")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    shutil.copy2(browser_path, tmp.name)
    con = sqlite3.connect(tmp.name)
    count = con.execute("SELECT count(*) FROM urls").fetchone()[0]
    top = con.execute("""
        SELECT url, visit_count FROM urls
        ORDER BY visit_count DESC LIMIT 5
    """).fetchall()
    con.close()
    os.unlink(tmp.name)
    print(f"\nChrome history: {count} URLs found\n")
    print("Your top 5 most visited sites:")
    for url, visits in top:
        print(f"  {visits:>6} visits — {url[:70]}")
else:
    print("Browser: not found (Chrome or Brave not installed?)")

# 3. Shell history
for h in [HOME/".zsh_history", HOME/".bash_history"]:
    if h.exists():
        lines = h.read_text(errors="ignore").splitlines()
        print(f"\nShell history: {len(lines)} commands found  ✓")
        break

# 4. Cursor / VS Code
cursor_db = HOME / "Library/Application Support/Cursor/User/globalStorage/state.vscdb"
vscode_db = HOME / "Library/Application Support/Code/User/globalStorage/state.vscdb"
if cursor_db.exists():
    print(f"Cursor:  found  ✓")
elif vscode_db.exists():
    print(f"VS Code: found  ✓")

print("\n=== All checks done ===")
print("If you see browser data above — LDP is ready.")
print("Next: copy ldp_server.py path into .cursor/mcp.json\n")
