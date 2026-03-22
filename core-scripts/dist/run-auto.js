import { autoGenCLI } from "./auto-connector.js";
async function main() {
    await autoGenCLI();
}
main().catch(console.error);
