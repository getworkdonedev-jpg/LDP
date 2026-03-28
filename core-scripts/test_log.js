import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const scriptPath = path.join(__dirname, "ldp_server.py");

const out = fs.openSync('debug.log', 'a');
const child = spawn("python3", [scriptPath], { detached: true, stdio: ['ignore', out, out] });
child.unref();
