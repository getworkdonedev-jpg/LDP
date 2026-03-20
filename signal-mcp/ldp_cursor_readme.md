# LDP — Local Data Protocol for Cursor

Reads your local Mac data directly into Cursor AI.
Zero cloud upload. Pure Python. No dependencies.

## Quick Start (2 minutes)

```bash
# Step 1 — run setup
bash setup.sh

# Step 2 — restart Cursor

# Step 3 — ask Cursor anything about your local data
```

## What Cursor can now answer

| Question | Data source |
|---|---|
| "What sites do I waste time on?" | Chrome/Brave history |
| "What did I work on this week?" | Git log + VS Code recent files |
| "What commands have I run recently?" | Shell history (zsh/bash) |
| "What apps are eating my CPU?" | Running processes |
| "Find all my Python files" | File search |
| "What databases are on my Mac?" | SQLite scanner |
| "How much disk space am I using?" | Disk usage |

## Tools registered in Cursor

- `ldp_chrome_history` — most visited URLs
- `ldp_recent_sites` — last N days browsing  
- `ldp_time_wasters` — top sites by visit count
- `ldp_shell_history` — recent terminal commands
- `ldp_vscode_recent` — recently opened files
- `ldp_git_log` — commit history for any repo
- `ldp_running_apps` — CPU/memory by process
- `ldp_find_files` — search files by pattern
- `ldp_scan_databases` — find all SQLite on Mac
- `ldp_disk_usage` — directory size breakdown

## Privacy

All reads happen locally. Nothing is uploaded.
The MCP server is a local process — Cursor talks to it
over stdin/stdout on your own machine.

## Add more data sources

Edit `ldp_server.py` — add a new function + entry in TOOLS + TOOL_MAP.
Takes ~15 lines per new data source.
