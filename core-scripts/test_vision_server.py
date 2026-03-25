# test_vision_server.py
import json
import base64
import os
import platform
import subprocess
from ldp_server import tool_vision_scan

def test_vision_scan():
    print("Testing ldp_vision_scan tool...")
    if platform.system() != "Darwin":
        print("  ~ Skipping (Vision Bridge only for macOS)")
        return

    args = {"app_name": "Test App"}
    try:
        res_raw = tool_vision_scan(args)
        res = json.loads(res_raw)

        if res.get("status") == "SUCCESS":
            print("  ✓ Vision scan tool success.")
            print(f"  ✓ App: {res['app']}")
            print(f"  ✓ Payload preview: {res['_vision_payload_preview']}")
        else:
            print(f"  ✖ Vision scan tool failed: {res.get('error')}")
            exit(1)
    except Exception as e:
        print(f"  ✖ Vision scan tool encountered an exception: {e}")
        exit(1)

if __name__ == "__main__":
    test_vision_scan()
