# LDP — Local Data Protocol

> Give any AI complete awareness of your Mac.
> Privately. Automatically. Zero upload.

[![npm](https://img.shields.io/npm/v/@ldp-protocol/sdk)](https://npmjs.com/package/@ldp-protocol/sdk)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## What LDP reads

| App | Data |
|-----|------|
| WhatsApp | 200K+ messages with contact names |
| iMessage | All messages |
| Apple Notes | All notes |
| Safari | Browse history |
| Chrome | Browse history with URLs |
| Calendar | All events |
| Contacts | Names, phones, emails |
| Apple Mail | All emails |
| Shell History | Terminal commands |
| Git | Commits across all repos |
| Reminders | All tasks |
| Signal | Messages (consent required) |
| System Logs | All system logs |

## Install — 3 steps

### Step 1 — Clone and install
```bash
git clone https://github.com/ldp-protocol/ldp-js
cd ldp-js/core-scripts
npm install
```

### Step 2 — Add API keys (free)
Get free keys:
- Groq: console.groq.com (free, fastest)
- Gemini: aistudio.google.com (free)

```bash
echo 'export GROQ_API_KEY="gsk_..."' >> ~/.zshrc
echo 'export GEMINI_API_KEY="AIza..."' >> ~/.zshrc
source ~/.zshrc
```

### Step 3 — Connect to Claude Desktop
Add to ~/Library/Application Support/Claude/claude_desktop_config.json:
```json
{
  "mcpServers": {
    "ldp": {
      "command": "python3",
      "args": ["/path/to/ldp-js/core-scripts/ldp_server.py"]
    }
  }
}
```
Restart Claude Desktop. Done.

## Ask Claude anything

```
"What did I work on yesterday?"
"Show my last 10 WhatsApp messages"
"What meetings do I have this week?"
"Tell me everything about John"
"What did I browse last night?"
```

## How it works

```
1. Scan    7 seconds — finds every database on your Mac
2. Identify  AI identifies each app — free, cached forever
3. Register  Every database becomes an MCP tool
4. Query     Claude reads locally — nothing leaves your Mac
```

## Privacy

- Zero data upload — ever
- All processing on your Mac
- Open source — verify every line
- Audit log of every access at ~/.ldp/audit.log
- Per-source consent — approve each app separately

## AI Teacher Cascade

LDP uses free AI to identify unknown databases:
```
1. Preloaded cache     instant, free
2. Groq llama-3.3-70b  free, 100rpm
3. Gemini 2.0 flash    free, 60rpm
4. Ollama local        free, offline
5. Claude              last resort only
Typical cost: $0.00
```

## Platform support

| Platform | Status |
|----------|--------|
| macOS | Full support |
| iOS | Spec published — contributors welcome |
| Android | Spec published — contributors welcome |
| Windows | Coming soon |

## Protocol spec
LDP is an open standard.
Build LDP for any platform:
See spec/LDP_PROTOCOL_v1.md

## Support
If LDP saves you time, star this repo.
Commercial use: getworkdonedev@gmail.com

## License
MIT — Karthik Perumalla 2026
Data Protocol (LDP) project.*
