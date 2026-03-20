import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";

async function brute() {
  const _sqlcipher: any = await import("@journeyapps/sqlcipher");
  const sqlcipher = _sqlcipher.default || _sqlcipher;
  
  const key = execSync('security find-generic-password -s "Signal Safe Storage" -w').toString().trim();
  const dbPath = path.join(os.homedir(), "Library/Application Support/Signal/sql/db.sqlite");
  const tmp = path.join(os.tmpdir(), `ldp_signal_brute_${Date.now()}.db`);
  fs.copyFileSync(dbPath, tmp);

  const configs = [
    [`PRAGMA key = "x'${key}'"`],
    [`PRAGMA key = "x'${key}'"`, `PRAGMA cipher_compatibility = 3`],
    [`PRAGMA key = "x'${key}'"`, `PRAGMA cipher_compatibility = 4`],
    [`PRAGMA key = "${key}"`],
    [`PRAGMA key = "${key}"`, `PRAGMA cipher_compatibility = 3`],
    [`PRAGMA key = "x'${key}'"`, `PRAGMA cipher_page_size = 4096`, `PRAGMA kdf_iter = 64000`],
    [`PRAGMA key = "x'${key}'"`, `PRAGMA cipher_page_size = 4096`, `PRAGMA kdf_iter = 1`],
    [`PRAGMA key = "x'${key}'"`, `PRAGMA cipher_page_size = 1024`, `PRAGMA kdf_iter = 64000`],
    [`PRAGMA key = "v4:x'${key}'"`],
    [`PRAGMA key = "v3:x'${key}'"`]
  ];

  let success = false;
  for (const pragmas of configs) {
    console.log("Trying:", pragmas);
    try {
      const res = await new Promise((resolve, reject) => {
        const db = new sqlcipher.Database(tmp, sqlcipher.OPEN_READONLY, (err: any) => {
          if (err) return reject(err);
          
          let i = 0;
          function next() {
            if (i >= pragmas.length) {
              db.all("SELECT count(*) FROM messages", (err2: any, res: any) => {
                db.close();
                if (err2) reject(err2); else resolve(res);
              });
              return;
            }
            db.run(pragmas[i++], (err: any) => {
              if (err) reject(err); else next();
            });
          }
          next();
        });
      });
      console.log("SUCCESS WITH:", pragmas, res);
      success = true;
      break;
    } catch (e: any) {
      console.log("Failed:", e.message);
    }
  }
  
  if (!success) {
    console.log("All configurations failed to decrypt the database.");
  }
  fs.unlinkSync(tmp);
}

brute().catch(console.error);
