import os, sys
sys.path.append(os.path.dirname(__file__))
import ldp_server # type: ignore
import json

print("\n--- Testing ldp_fused_whatsapp_query ---")
res = ldp_server.tool_fused_whatsapp_query({"limit": 5})
print(res[:500])

print("\n--- Testing ldp_fused_context ---")
query_res = [
    {"text": "Hey call me at +1 555-123-4567 or 1234567890"}, 
    {"file": "/Users/karthikperumalla/Desktop/LDP/core-scripts/ldp_server.py"}
]
res2 = ldp_server.tool_fused_context({"query_result": query_res})
print(res2)
