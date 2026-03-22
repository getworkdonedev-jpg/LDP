import { LDPBrain } from "./brain.js";
import * as path from "node:path";
import * as os from "node:os";

async function runSignal() {
  console.log("Testing Strategic Signal Decryption via Brain...\n");
  const brain = new LDPBrain({ verbose: true });
  
  const signalPath = path.join(os.homedir(), "Library/Application Support/Signal/sql/db.sqlite");
  
  console.log(`Solving decryption for: ${signalPath}`);
  const solve = await brain.decrypt.solve(signalPath, "Signal", true);
  
  if (!solve || !solve.key) {
    console.error("Brain failed to solve Signal decryption!");
    return;
  }
  
  console.log(`\n🎉 BRAIN SOLVED IT! Strategy: ${solve.method}`);
  console.log(`Key: [redacted for security]`);
}

runSignal().catch(console.error);
