# @ldp-protocol/sdk

**LDP — Local Data Protocol**

Use MCP for cloud tools. Use LDP for local data.

```bash
npm install @ldp-protocol/sdk
```

```ts
import { LDPEngine } from "@ldp-protocol/sdk";
import { SyntheticChromeConnector } from "@ldp-protocol/sdk/connectors";

const engine = new LDPEngine().start();
engine.register(new SyntheticChromeConnector());
engine.grantConsent("chrome");

await engine.connect("chrome");
const result = await engine.query("what sites did I waste time on this week");
// Your Chrome history — never left your machine.
```

---

## Why LDP

Every personal AI today either knows nothing about you, or sends your data to a cloud server. LDP is the third option: AI that reads your personal data locally, reasons over it, and answers — without any of it leaving your device.

| | MCP | LDP |
|---|---|---|
| Chrome history | ✗ | ✓ auto-discovered |
| Spotify cache | ✗ | ✓ local SQLite |
| Bank exports | ✗ | ✓ CSV/PDF local |
| Phone data | ✗ | ✓ ADB bridge |
| Privacy default | cloud | **local** |
| Encryption | none | AES-256-GCM |
| New connector | 120 lines + 4hrs | 15-line JSON + 15min |

---

## Install

```bash
npm install @ldp-protocol/sdk        # npm
yarn add @ldp-protocol/sdk           # yarn
pnpm add @ldp-protocol/sdk           # pnpm
```

Requires Node.js 18+.

---

## Quickstart

### Connect and query

```ts
import { LDPEngine } from "@ldp-protocol/sdk";
import { ChromeConnector } from "@ldp-protocol/sdk/connectors";

const engine = new LDPEngine().start();
engine.register(new ChromeConnector());

// Show consent request to user before reading
const request = engine.requestConsent("chrome");
console.log(request.prompt); // "LDP wants to read your Google Chrome data..."

// User approves
engine.grantConsent("chrome");
await engine.connect("chrome");

const result = await engine.query("what have I been researching this week");
for (const chunk of result.payload.chunks) {
  console.log(chunk); // { url, title, visit_count, ... }
}

engine.stop();
```

### Multiple sources

```ts
import { LDPEngine, RiskTier } from "@ldp-protocol/sdk";
import {
  ChromeConnector,
  SyntheticBankingConnector,
  SyntheticSpotifyConnector,
} from "@ldp-protocol/sdk/connectors";

const engine = new LDPEngine().start();
engine.register(new ChromeConnector());
engine.register(new SyntheticBankingConnector());
engine.register(new SyntheticSpotifyConnector());

engine.grantConsent("chrome");
engine.grantConsent("banking");
engine.grantConsent("spotify");

await engine.connect("chrome");
await engine.connect("banking");
await engine.connect("spotify");

// Cross-source query — all three at once
const result = await engine.query("what have I been doing this week");
console.log(result.payload.sources);  // ["chrome", "banking", "spotify"]
console.log(result.payload.packedRows); // relevance-ranked rows from all sources
```

### Write actions with approval

```ts
const engine = new LDPEngine({
  approvalCb: async (msg) => {
    // Show user the action — return true to approve
    console.log(`Approve: ${msg.payload.action}?`);
    return await getUserConfirmation();
  }
}).start();

// LOW risk — auto approved
await engine.writeIntent("save_note", { text: "reminder" }, RiskTier.LOW);

// HIGH risk — triggers approvalCb
await engine.writeIntent("post_tweet", { text: "..." }, RiskTier.HIGH);
```

### With MCP (expose to Claude Desktop, Cursor, etc.)

```ts
import { LDPEngine } from "@ldp-protocol/sdk";
import { MCPAdapter } from "@ldp-protocol/sdk/adapters";
import { ChromeConnector } from "@ldp-protocol/sdk/connectors";

const engine  = new LDPEngine().start();
engine.register(new ChromeConnector());
engine.grantConsent("chrome");
await engine.connect("chrome");

const adapter = new MCPAdapter(engine);

// Drop into any MCP server
const { tools } = adapter.listTools();
// tools = [{ name: "ldp_chrome_query", ... }, { name: "ldp_cross_query", ... }]

const result = await adapter.callTool("ldp_chrome_query", {
  question: "top sites this week"
});
```

### Build your own connector

```ts
import type { BaseConnector, ConnectorDescriptor } from "@ldp-protocol/sdk/connectors";
import { findFirst } from "@ldp-protocol/sdk/connectors";

class ObsidianConnector implements BaseConnector {
  descriptor: ConnectorDescriptor = {
    name:         "obsidian",
    app:          "Obsidian",
    version:      "1.0",
    dataPaths:    ["~/.config/obsidian/*.sqlite", "~/Library/Application Support/obsidian/*.sqlite"],
    permissions:  ["notes.read"],
    namedQueries: { recent_notes: "Notes edited this week" },
    description:  "Obsidian vault — local notes, never uploaded.",
  };

  private dbPath: string | null = null;

  async discover() {
    this.dbPath = findFirst(this.descriptor.dataPaths);
    return this.dbPath !== null;
  }

  async schema() {
    return { notes: { title: "note title", content: "note body", modified: "last modified" } };
  }

  async read(query: string, limit = 500) {
    // your SQLite reading logic
    return [];
  }
}
```

### CLI

```bash
npx ldp start                            # show available apps
npx ldp connect chrome                   # connect (asks for consent)
npx ldp query "where do I waste time"    # query connected sources
npx ldp status                           # engine stats
npx ldp audit                            # encrypted audit log
```

---

## Security

- **AES-256-GCM** — all data at rest encrypted
- **Consent required** — no read without explicit approval
- **Audit log** — every read and write intent recorded (encrypted)
- **Tiered approval** — READ/LOW auto, MEDIUM/HIGH needs confirmation
- **Tamper detection** — GCM auth tag catches any file modification
- **No plaintext on disk** — verified in test suite

---

## Links

- Docs: [ldp-protocol.dev](https://ldp-protocol.dev)
- GitHub: [github.com/ldp-protocol/ldp-js](https://github.com/ldp-protocol/ldp-js)
- Python SDK: [github.com/ldp-protocol/ldp](https://github.com/ldp-protocol/ldp)
- Protocol spec: [github.com/ldp-protocol/spec](https://github.com/ldp-protocol/spec)

---

## License

MIT
