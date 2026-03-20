import { autoGenCLI } from "./auto-connector.ts";
async function main() {
    await autoGenCLI();
}
main().catch(console.error);
