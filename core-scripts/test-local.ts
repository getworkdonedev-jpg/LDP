import { LDPEngine } from "./engine.js";
import { ChromeConnector } from "./chrome.js";

async function main() {
  console.log("Initializing LDP Engine with REAL Chrome Connector...");
  const engine = new LDPEngine().start();
  
  // Initialize the real Chrome connector
  const chrome = new ChromeConnector();
  
  console.log("\n1. Discovering local Chrome databases...");
  const found = await chrome.discover();
  if (!found) {
    console.log("Chrome history not found on this machine.");
    return;
  }
  
  console.log("2. Registering connector...");
  engine.register(chrome);
  
  console.log("3. Granting consent...");
  engine.grantConsent("chrome");
  
  console.log("4. Connecting...");
  await engine.connect("chrome");
  
  console.log("5. Querying 'recent_tabs'...");
  const recentTabs = await engine.query("recent_tabs");
  
  console.log("\n--- RESULT ---");
  // Only print the first 3 chunks so we don't spam the terminal
  if (recentTabs.payload && Array.isArray(recentTabs.payload.chunks)) {
    console.log(JSON.stringify(recentTabs.payload.chunks.slice(0, 3), null, 2));
    console.log(`... and ${Math.max(0, recentTabs.payload.chunks.length - 3)} more rows.`);
  } else {
    console.log(JSON.stringify(recentTabs, null, 2));
  }
  
  engine.stop();
}

main().catch(console.error);
