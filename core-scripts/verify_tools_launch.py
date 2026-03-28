import subprocess, json, sys, os

TOOLS_TO_TEST = [
    "ldp_chrome_history_query",
    "ldp_imessage_query",
    "ldp_whatsapp_query",
    "ldp_notes_query",
    "ldp_calendar_query",
    "ldp_contacts_query",
    "ldp_shell_history_query",
    "ldp_git_log_query",
    "ldp_mail_query",
    "ldp_reminders_query"
]

def run_tool(name, args={}):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": args
        }
    }
    input_str = json.dumps(payload) + "\n"
    # Note: This assumes the server is not already running or we run it in a subprocess
    process = subprocess.Popen(
        ["python3", "ldp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd="core-scripts"
    )
    # Give it a second to start (though main() reads line by line)
    stdout, stderr = process.communicate(input=input_str, timeout=10)
    return stdout, stderr

def main():
    print("Starting LDP Tool Verification...")
    for tool in TOOLS_TO_TEST:
        print(f"Testing {tool}...", end=" ", flush=True)
        try:
            # We use limit=2 as requested
            stdout, stderr = run_tool(tool, {"limit": 2})
            if not stdout:
                print(f"FAILED (No output). Stderr: {stderr}")
                continue
            
            # Find the JSON response in stdout (it might have some stderr-like junk at the start)
            lines = stdout.strip().split("\n")
            res_json = None
            for line in lines:
                if line.startswith('{"jsonrpc"'):
                    res_json = json.loads(line)
                    break
            
            if not res_json:
                print(f"FAILED (No JSON response). Raw: {stdout[:100]}")
                continue
                
            if "error" in res_json or res_json.get("result", {}).get("isError"):
                print(f"FAILED (Error returned). Result: {res_json.get('result', {}).get('content')}")
                continue
                
            content = res_json.get("result", {}).get("content", [{}])[0].get("text", "")
            if not content or "No " in content or "Error" in content or "Not found" in content:
                 print(f"FAILED (Empty or No-data message). Content: {content[:100]}")
            else:
                 print("PASSED")
                 # print(f"DEBUG Output: {content[:100]}...")
        except Exception as e:
            print(f"ERROR: {e}")

if __name__ == "__main__":
    main()
