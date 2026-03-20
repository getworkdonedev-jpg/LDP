import { SignalConnector } from "./signal.ts";
async function runSignal() {
    console.log("Testing Signal Connector...\n");
    const conn = new SignalConnector();
    const found = await conn.discover();
    if (!found) {
        console.error("Signal DB not found!");
        return;
    }
    console.log("Signal DB found!\n");
    const rows = await conn.read("recent messages", 10);
    console.log(`\n🎉 READ ${rows.length} MESSAGES FROM SIGNAL!\n`);
    console.log("=".repeat(60));
    for (const row of rows) {
        const date = new Date(Number(row.sent_at)).toLocaleString();
        console.log(`[${date}] (${row.type}) ${String(row.body).substring(0, 80)}`);
    }
    console.log("=".repeat(60));
    const convos = await conn.read("conversations active", 5);
    console.log(`\n📋 ${convos.length} CONVERSATIONS:\n`);
    for (const c of convos) {
        console.log(`  • ${c.name}`);
    }
}
runSignal().catch(console.error);
