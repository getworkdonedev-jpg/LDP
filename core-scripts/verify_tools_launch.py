import subprocess
import json
import sys
import os
from typing import Any, Dict, List, Optional, Tuple, cast

TOOLS_TO_TEST: List[str] = [
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

def run_tool(name: str, args: Dict[str, Any] = {}) -> Tuple[Optional[str], Optional[str]]:
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
    try:
        process = subprocess.Popen(
            ["python3", "ldp_server.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd="."
        )
        stdout, stderr = process.communicate(input=input_str, timeout=15)
        return stdout, stderr
    except Exception as e:
        return None, str(e)

def main() -> None:
    print("Starting LDP Tool Verification...")
    for tool in TOOLS_TO_TEST:
        print(f"Testing {tool}...", end=" ", flush=True)
        try:
            raw_stdout, raw_stderr = run_tool(tool, {"limit": 2})
            
            if raw_stdout is None:
                err_str = str(raw_stderr or "Unknown spawn error")
                print(f"FAILED (Spawn error). Stderr: {err_str}")
                continue
            
            stdout_str: str = raw_stdout
            if not stdout_str.strip():
                err_str = str(raw_stderr or "No output")
                print(f"FAILED (No output). Stderr: {err_str}")
                continue
            
            # Find the JSON response in stdout
            res_json: Optional[Dict[str, Any]] = None
            for line in stdout_str.strip().split("\n"):
                if line.startswith('{"jsonrpc"'):
                    try:
                        parsed = json.loads(line)
                        if isinstance(parsed, dict):
                            res_json = cast(Dict[str, Any], parsed)
                            break
                    except json.JSONDecodeError:
                        continue
            
            if res_json is None:
                snippet = stdout_str[:50]
                print(f"FAILED (No JSON response). Raw: {snippet}")
                continue
            
            # Re-bind for Pyre narrowing
            current_res: Dict[str, Any] = res_json
            
            # Check for JSON-RPC error
            if "error" in current_res:
                err_rpc = current_res.get("error")
                print(f"FAILED (RPC Error). Error: {err_rpc}")
                continue
                
            result = current_res.get("result")
            if not isinstance(result, dict):
                print(f"FAILED (Malformed result). Result: {result}")
                continue
            
            current_result: Dict[str, Any] = result
            if current_result.get("isError"):
                err_content = current_result.get("content")
                print(f"FAILED (Tool-level error). Content: {err_content}")
                continue
                
            content_list = current_result.get("content")
            if not isinstance(content_list, list) or not content_list:
                print("FAILED (Empty or malformed content list)")
                continue

            first_item = content_list[0]
            if not isinstance(first_item, dict):
                print("FAILED (Malformed content item)")
                continue

            # Ensure text is string before slicing
            text_val = first_item.get("text")
            content_text = str(text_val) if text_val is not None else ""
            
            if not content_text or any(x in content_text for x in ["No ", "Error", "Not found"]):
                 snippet_text = content_text[:50]
                 print(f"FAILED (No data). Content: {snippet_text}")
            else:
                 print("PASSED")
                 
        except Exception as e:
            print(f"ERROR in test loop: {e}")

if __name__ == "__main__":
    main()
