/**
 * LDP AutoConnectorGenerator — test suite
 * Tests: fingerprint detection, heuristic fallback, schema reader, AI mock
 */

import * as fs   from "node:fs";
import * as path from "node:path";
import * as os   from "node:os";
import { AutoConnectorGenerator, autoGenCLI } from "./auto-connector.js";

// ── Minimal SQLite file builder (writes valid magic header + fake CREATE TABLE) ──

function writeFakeSQLite(dir: string, name: string, createSQL: string): string {
  const filePath = path.join(dir, name);
  // SQLite header: magic string + page size 4096 (bytes 16-17) + rest zeros
  const buf = Buffer.alloc(4096, 0);
  buf.write("SQLite format 3\0", 0, "ascii");
  buf.writeUInt16BE(4096, 16); // page size
  buf.writeUInt8(1, 18);       // file format write version
  buf.writeUInt8(1, 19);       // file format read version

  // Append CREATE TABLE statement as text (schema parser reads raw bytes)
  const sqlBuf = Buffer.from(createSQL, "utf8");
  const combined = Buffer.concat([buf, sqlBuf]);
  fs.writeFileSync(filePath, combined);
  return filePath;
}

// ── Test runner ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const errors: string[] = [];

async function test(name: string, fn: () => Promise<void> | void) {
  const start = Date.now();
  try {
    await fn();
    const ms = Date.now() - start;
    console.log(`  ✓  ${name} (${ms}ms)`);
    passed++;
  } catch (err: unknown) {
    const ms = Date.now() - start;
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`  ✗  ${name} (${ms}ms)`);
    console.log(`       ${msg}`);
    errors.push(`${name}: ${msg}`);
    failed++;
  }
}

function assert(condition: boolean, msg: string) {
  if (!condition) throw new Error(msg);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ldp-autogen-"));

async function runTests() {
  console.log("\n── LDP AutoConnectorGenerator — test suite ──────────────────\n");

  // ─ 1. Known fingerprint: Chrome ──────────────────────────────────────────
  console.log("Known app fingerprints");

  await test("Chrome path detected via fingerprint", async () => {
    const fakePath = path.join(tmpDir, "Google", "Chrome", "Default", "History");
    fs.mkdirSync(path.dirname(fakePath), { recursive: true });
    writeFakeSQLite(
      path.dirname(fakePath),
      "History",
      `CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);
       CREATE TABLE visits (id INTEGER, url INTEGER, visit_time INTEGER, from_visit INTEGER);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect Chrome");
    assert(result!.method === "known-app", `Expected known-app, got ${result!.method}`);
    assert(result!.confidence >= 0.9, `Confidence too low: ${result!.confidence}`);
    assert(result!.descriptor.app.includes("Chrome"), `App name wrong: ${result!.descriptor.app}`);
    assert("time_wasters" in result!.descriptor.namedQueries, "Missing time_wasters query");
    assert("typed_urls"   in result!.descriptor.namedQueries, "Missing typed_urls query");
  });

  await test("WhatsApp path detected via fingerprint", async () => {
    const wsDir = path.join(tmpDir, "group.net.whatsapp.WhatsApp.shared");
    fs.mkdirSync(wsDir, { recursive: true });
    const fakePath = writeFakeSQLite(wsDir, "ChatStorage.sqlite",
      `CREATE TABLE ZWAMESSAGE (Z_PK INTEGER, ZTEXT TEXT, ZFROMJID TEXT, ZTOJID TEXT, ZMESSAGEDATE REAL);
       CREATE TABLE ZWACHATSESSION (Z_PK INTEGER, ZCONTACTJID TEXT, ZLASTMESSAGEDATE REAL);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect WhatsApp");
    assert(result!.descriptor.app === "WhatsApp", `Wrong app: ${result!.descriptor.app}`);
    assert("top_contacts" in result!.descriptor.namedQueries, "Missing top_contacts query");
  });

  await test("Spotify path detected via fingerprint", async () => {
    const spDir = path.join(tmpDir, "Spotify", "PersistentCache");
    fs.mkdirSync(spDir, { recursive: true });
    const fakePath = writeFakeSQLite(spDir, "podcasts.db",
      `CREATE TABLE playback_history (id INTEGER, track_uri TEXT, play_count INTEGER, ms_played INTEGER, ts_played INTEGER);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect Spotify");
    assert(result!.descriptor.app === "Spotify", `Wrong app: ${result!.descriptor.app}`);
  });

  // ─ 2. Heuristic fallback (unknown paths, recognisable schema) ────────────
  console.log("\nHeuristic analysis (no AI)");

  await test("Browser history schema → heuristic detection", async () => {
    const fakeDir = path.join(tmpDir, "some_unknown_browser");
    fs.mkdirSync(fakeDir, { recursive: true });
    const fakePath = writeFakeSQLite(fakeDir, "webdata.db",
      `CREATE TABLE urls (id INTEGER, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0, last_visit_time INTEGER NOT NULL);
       CREATE TABLE visits (id INTEGER, url INTEGER NOT NULL, visit_time INTEGER NOT NULL);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect via heuristic");
    assert(result!.method === "heuristic", `Expected heuristic, got ${result!.method}`);
    assert(result!.confidence >= 0.6, `Confidence too low: ${result!.confidence}`);
    assert("most_visited" in result!.descriptor.namedQueries, "Missing most_visited query");
  });

  await test("Messaging schema → heuristic detection", async () => {
    const msgDir = path.join(tmpDir, "some_messenger_app");
    fs.mkdirSync(msgDir, { recursive: true });
    const fakePath = writeFakeSQLite(msgDir, "messages.db",
      `CREATE TABLE messages (message_id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, body TEXT, timestamp INTEGER);
       CREATE TABLE conversations (id INTEGER, participants TEXT);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect messaging app");
    assert(result!.confidence >= 0.5, `Low confidence: ${result!.confidence}`);
    assert("recent_messages" in result!.descriptor.namedQueries, "Missing recent_messages query");
  });

  await test("Finance schema → heuristic detection", async () => {
    const finDir = path.join(tmpDir, "my_finance_app");
    fs.mkdirSync(finDir, { recursive: true });
    const fakePath = writeFakeSQLite(finDir, "accounts.db",
      `CREATE TABLE transactions (id INTEGER, amount REAL, merchant TEXT, account_id INTEGER, balance REAL, date INTEGER);
       CREATE TABLE accounts (account_id INTEGER, name TEXT, balance REAL);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect finance app");
    assert("recent_transactions" in result!.descriptor.namedQueries, "Missing recent_transactions");
  });

  await test("Calendar schema → heuristic detection", async () => {
    const calDir = path.join(tmpDir, "calendar_data");
    fs.mkdirSync(calDir, { recursive: true });
    const fakePath = writeFakeSQLite(calDir, "events.db",
      `CREATE TABLE events (event_id INTEGER, summary TEXT, dtstart INTEGER, dtend INTEGER, location TEXT);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect calendar");
    assert("upcoming_events" in result!.descriptor.namedQueries, "Missing upcoming_events");
  });

  await test("Notes schema → heuristic detection", async () => {
    const notesDir = path.join(tmpDir, "notes_data");
    fs.mkdirSync(notesDir, { recursive: true });
    const fakePath = writeFakeSQLite(notesDir, "notes.db",
      `CREATE TABLE notes (note_id INTEGER, title TEXT, content TEXT, created_at INTEGER, modified_at INTEGER);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should detect notes app");
    assert("recent_notes" in result!.descriptor.namedQueries, "Missing recent_notes");
  });

  // ─ 3. Edge cases ─────────────────────────────────────────────────────────
  console.log("\nEdge cases");

  await test("Non-SQLite file returns null", async () => {
    const badPath = path.join(tmpDir, "notadb.db");
    fs.writeFileSync(badPath, "this is not a database file at all");

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(badPath);
    assert(result === null, "Should return null for non-SQLite file");
  });

  await test("Empty SQLite file returns null", async () => {
    const emptyPath = path.join(tmpDir, "empty.sqlite");
    const buf = Buffer.alloc(100, 0);
    buf.write("SQLite format 3\0", 0, "ascii");
    buf.writeUInt16BE(4096, 16);
    fs.writeFileSync(emptyPath, buf);

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(emptyPath);
    assert(result === null, "Should return null for empty schema");
  });

  await test("Locked / missing file handled gracefully", async () => {
    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile("/nonexistent/path/fake.db");
    assert(result === null, "Should return null for missing file");
  });

  await test("System cache dirs are skipped in scan", async () => {
    const cacheDir = path.join(tmpDir, "Cache");
    fs.mkdirSync(cacheDir, { recursive: true });
    writeFakeSQLite(cacheDir, "cache.db",
      `CREATE TABLE urls (id INTEGER, url TEXT, visit_count INTEGER);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const results = await gen.scan();

    // Cache dir should be skipped — none of the results should be from Cache/
    const fromCache = results.filter(r => r.sourcePath.includes("/Cache/"));
    assert(fromCache.length === 0, `Cache dir not skipped: ${fromCache.map(r => r.sourcePath).join(", ")}`);
  });

  // ─ 4. Connector usability ─────────────────────────────────────────────────
  console.log("\nConnector usability");

  await test("Generated connector has valid descriptor shape", async () => {
    const testDir = path.join(tmpDir, "test_connector");
    fs.mkdirSync(testDir, { recursive: true });
    const fakePath = writeFakeSQLite(testDir, "history.db",
      `CREATE TABLE urls (id INTEGER, url TEXT, visit_count INTEGER, last_visit_time INTEGER);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should generate result");
    const d = result!.descriptor;
    assert(typeof d.name === "string" && d.name.length > 0, "name must be a string");
    assert(typeof d.app  === "string" && d.app.length  > 0, "app must be a string");
    assert(Array.isArray(d.dataPaths)   && d.dataPaths.length  > 0, "dataPaths required");
    assert(Array.isArray(d.permissions) && d.permissions.length > 0, "permissions required");
    assert(typeof d.namedQueries === "object" && Object.keys(d.namedQueries).length >= 2, "namedQueries required (min 2)");
    assert(typeof d.description === "string", "description must be a string");
  });

  await test("Generated connector.read() returns rows", async () => {
    const testDir2 = path.join(tmpDir, "test_read");
    fs.mkdirSync(testDir2, { recursive: true });
    const fakePath = writeFakeSQLite(testDir2, "msgs.db",
      `CREATE TABLE messages (message_id INTEGER, sender TEXT, body TEXT, timestamp INTEGER);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should generate result");
    const rows = await result!.connector.read("recent_messages");
    assert(Array.isArray(rows), "read() must return array");
  });

  await test("connector.connect() succeeds when file exists", async () => {
    const testDir3 = path.join(tmpDir, "test_connect");
    fs.mkdirSync(testDir3, { recursive: true });
    const fakePath = writeFakeSQLite(testDir3, "data.db",
      `CREATE TABLE events (id INTEGER, summary TEXT, dtstart INTEGER);`
    );

    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });
    const result = await gen.generateForFile(fakePath);

    assert(result !== null, "Should generate result");
    await result!.connector.discover(); // should not throw
    assert(true, "discover() succeeded");
  });

  await test("connector.connect() throws when file missing", async () => {
    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir] });

    // Build a connector manually pointing at a nonexistent path
    const fakePath = path.join(tmpDir, "nonexistent_after_scan.db");
    // Create temporarily, generate, then delete
    fs.mkdirSync(tmpDir, { recursive: true });
    writeFakeSQLite(tmpDir, "nonexistent_after_scan.db",
      `CREATE TABLE urls (id INTEGER, url TEXT, visit_count INTEGER);`
    );

    const result = await gen.generateForFile(fakePath);
    assert(result !== null, "Should generate");

    // Now delete the file
    fs.unlinkSync(fakePath);

    const success = await result!.connector.discover();
    assert(!success, "discover() should return false when source file deleted");
  });

  // ─ 5. Full scan ───────────────────────────────────────────────────────────
  console.log("\nFull scan");

  await test("scan() returns deduplicated results sorted by confidence", async () => {
    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir], maxFiles: 100 });
    const results = await gen.scan();

    assert(Array.isArray(results), "scan() must return array");

    // All results above minimum threshold
    for (const r of results) {
      assert(r.confidence >= 0.3, `Result below threshold: ${r.descriptor.app} conf=${r.confidence}`);
    }

    // Sorted descending
    for (let i = 1; i < results.length; i++) {
      assert(results[i].confidence <= results[i-1].confidence, "Results not sorted by confidence");
    }

    // No duplicate app names
    const apps = results.map(r => r.descriptor.app);
    const unique = new Set(apps);
    assert(apps.length === unique.size, `Duplicate apps: ${apps.join(", ")}`);
  });

  await test("scan() completes within 5 seconds", async () => {
    const start = Date.now();
    const gen = new AutoConnectorGenerator({ extraPaths: [tmpDir], maxFiles: 50 });
    await gen.scan();
    const ms = Date.now() - start;
    assert(ms < 5000, `Scan too slow: ${ms}ms`);
  });

  // ─ Cleanup ────────────────────────────────────────────────────────────────
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}

  // ─ Summary ───────────────────────────────────────────────────────────────
  console.log("\n─────────────────────────────────────────────────────────────");
  console.log(`\n  ${passed + failed} tests: ${passed} passed, ${failed} failed\n`);

  if (errors.length > 0) {
    console.log("Failures:");
    errors.forEach(e => console.log(`  - ${e}`));
    console.log();
    process.exit(1);
  }
}

runTests().catch(e => { console.error(e); process.exit(1); });
