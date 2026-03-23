const fs = require('fs');
let code = fs.readFileSync('scripts/train_brain.ts', 'utf-8');
code = code.replace('execSync("brew info --json=v2 --all-casks"', 'execSync("/opt/homebrew/bin/brew info --json=v2 --all-casks"');
fs.writeFileSync('scripts/train_brain.ts', code);
