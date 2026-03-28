import { SignalConnector } from "./signal.js";

async function main() {
    const connector = new SignalConnector();
    const found = await connector.discover();
    if (!found) {
        console.log(JSON.stringify({ error: "Signal database not found" }));
        return;
    }

    const type = process.argv[2] || "messages";
    try {
        const rows = await connector.read(type);
        console.log(JSON.stringify(rows));
    } catch (e: any) {
        console.log(JSON.stringify({ error: e.message }));
    }
}

main();
