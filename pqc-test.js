const admin = require('firebase-admin');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const os = require('os');

// Set Firestore Emulator environment variable
process.env.FIRESTORE_EMULATOR_HOST = 'localhost:8080';

// Initialize Firebase Admin
admin.initializeApp({
  projectId: 'ldp-1de86'
});

const db = admin.firestore();

/**
 * Simulates a Hybrid Post-Quantum Cryptography (PQC) payload wrap.
 * Uses SHA-256 HMAC for the traditional layer and wraps it in a 
 * mock 'ML-KEM-768' header for the quantum-safe simulation.
 */
function simulateHybridPQC(message, secret = 'ldp-quantum-vault-key-2026') {
  // Create SHA-256 HMAC
  const hmac = crypto.createHmac('sha256', secret)
                     .update(message)
                     .digest('hex');
  
  // Wrap in LDP-PQC-V1 header to simulate quantum-safe ciphertext
  return `LDP-PQC-V1<${hmac}>`;
}

async function runPQCTest() {
  console.log('Initializing LDP PQC Simulation...');

  try {
    // 4. Scan a local file to simulate data-gathering
    const zshrcPath = path.join(os.homedir(), '.zshrc');
    let scanContent = '';
    
    if (fs.existsSync(zshrcPath)) {
      console.log(`Scanning local file: ${zshrcPath}`);
      // Read first 20 lines to simulate data gathering
      const rawFile = fs.readFileSync(zshrcPath, 'utf8');
      scanContent = rawFile.split('\n').slice(0, 20).join('\n');
    } else {
      console.log('No .zshrc found. Using dummy system telemetry for scan...');
      scanContent = `SYSTEM_SCAN_FALLBACK: ${os.platform()} | ${os.release()} | ${os.arch()}`;
    }

    // 3. Encrypt the scanned data using Hybrid PQC simulation
    const encryptedPayload = simulateHybridPQC(scanContent);
    
    // 5. 'Upload' to the local pqc_vault collection
    const docRef = await db.collection('pqc_vault').add({
      payload: encryptedPayload,
      scannedAt: new admin.firestore.Timestamp(Math.floor(Date.now() / 1000), 0),
      originalSource: zshrcPath,
      hostname: os.hostname()
    });

    // 6. Print verification details
    console.log('\n✅ PQC Vault Upload Successful!');
    console.log('----------------------------------------------------');
    console.log(`Document ID:        ${docRef.id}`);
    console.log(`Encrypted Payload:  ${encryptedPayload}`);
    console.log('----------------------------------------------------');
    console.log('Verify at your local Emulator UI: http://localhost:4000');
    console.log('----------------------------------------------------');

  } catch (error) {
    console.error('❌ PQC Test Failed:', error);
  }
}

runPQCTest();
