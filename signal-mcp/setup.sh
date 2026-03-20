#!/bin/bash
# LDP Setup for Cursor — run once on your Mac
# Usage: bash setup.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LDP_PATH="$SCRIPT_DIR/ldp_server.py"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   LDP — Cursor MCP Setup             ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. Check Python
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    echo "✓  $PY_VER"
else
    echo "✗  Python3 not found — install from python.org"
    exit 1
fi

# 2. Test LDP
echo "   Running quick data test..."
python3 "$SCRIPT_DIR/test_ldp.py"

# 3. Find Cursor config dir
CURSOR_CONFIG="$HOME/.cursor"
CURSOR_APP="$HOME/Library/Application Support/Cursor"
if [ -d "$CURSOR_APP" ]; then
    echo "✓  Cursor found"
else
    echo "⚠  Cursor not found at expected path"
    echo "   Make sure Cursor is installed: https://cursor.sh"
fi

# 4. Write mcp.json
mkdir -p "$CURSOR_CONFIG"
cat > "$CURSOR_CONFIG/mcp.json" << MCPEOF
{
  "mcpServers": {
    "ldp": {
      "command": "python3",
      "args": ["$LDP_PATH"]
    }
  }
}
MCPEOF

echo ""
echo "✓  Written to: $CURSOR_CONFIG/mcp.json"
echo "   Server path: $LDP_PATH"
echo ""
echo "╔══════════════════════════════════════╗"
echo "║  DONE — 2 steps left:                ║"
echo "║  1. Quit Cursor completely            ║"
echo "║  2. Reopen Cursor                     ║"
echo "║  3. Open a chat → type:               ║"
echo "║     'what sites do I visit most?'     ║"
echo "╚══════════════════════════════════════╝"
echo ""
