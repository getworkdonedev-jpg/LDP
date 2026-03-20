const { app, safeStorage } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');

app.name = "Signal";

app.whenReady().then(() => {
  try {
    const configPath = path.join(os.homedir(), "Library/Application Support/Signal/config.json");
    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    const encryptedHex = config.encryptedKey;
    if (!encryptedHex) throw new Error("No encryptedKey in config.json");

    const encrypted = Buffer.from(encryptedHex, "hex");
    
    if (!safeStorage.isEncryptionAvailable()) {
      console.log("Encryption not available.");
      app.exit(1);
      return;
    }

    const decryptedString = safeStorage.decryptString(encrypted);
    console.log("=== DECRYPTED PAYLOAD ===");
    console.log(`Length (characters): ${decryptedString.length}`);
    console.log(`String: ${decryptedString}`);
    console.log("=========================");

  } catch (e) {
    console.error("Error decrypting:", e);
  }
  app.exit(0);
});
