import json
import subprocess
import os
import typing
from typing import Any

TOOLS_TO_TEST = [
    "ldp_chrome_history_query",
    "ldp_imessage_query",
    "ldp_notes_query",
    "ldp_calendar_query",
    "ldp_contacts_query",
    "ldp_shell_history_query",
    "ldp_git_log_query"
]

def call_tool(tool_name):
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {"limit": 2}
        }
    }
    
    # We run ldp_server.py and feed it the request via stdin
    # We need to set the environment variables if needed, but it should work with defaults
    process = subprocess.Popen(
        ["python3", "core-scripts/ldp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=os.path.expanduser("~/Desktop/LDP")
    )
    
    # The server starts and prints some logs to stderr
    # We send the request
    stdout, stderr = process.communicate(input=json.dumps(req) + "\n")
    
    return stdout, stderr

print("=== LDP Tool Verification ===")
for tool in TOOLS_TO_TEST:
    print(f"Testing {tool}...")
    stdout, stderr = call_tool(tool)
    
    # The output might have multiple lines, each a JSON response
    lines = stdout.strip().split("\n")
    found_resp = False
    for line in lines:
        try:
            resp = json.loads(line)
            if resp.get("id") == 1:
                content = resp.get("result", {}).get("content", [{}])[0].get("text", "")
                if "Error" in content or "Database not found" in content or "Database path not found" in content:
                    print(f"  ❌ FAILED: {content[:100]}")
                else:
                    print(f"  ✅ SUCCESS: {content.splitlines()[0] if content else 'Empty response'}")
                found_resp = True
                break
        except:
            continue
    
    if not found_resp:
        print(f"  ❓ NO RESPONSE. Stderr: {typing.cast(Any, str(stderr))[0:200]}")

print("=== End of Verification ===")
