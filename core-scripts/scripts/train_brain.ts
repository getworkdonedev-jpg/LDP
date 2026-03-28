import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { execSync } from "child_process";

const KNOWLEDGE_FILE = path.join(os.homedir(), "Desktop", "LDP", "core-scripts", "brain_knowledge.json");
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

interface GlobalAppKnowledge {
  appName: string;
  sources: Set<string>;
  pathPatterns: Set<string>;
  tableSignature: Set<string>;
  readStrategy?: string;
  epochConversion?: string;
  category?: string;
}

const GLOBAL_BASE: Record<string, GlobalAppKnowledge> = {};

function getApp(name: string): GlobalAppKnowledge {
  if (!GLOBAL_BASE[name]) {
    GLOBAL_BASE[name] = {
      appName: name,
      sources: new Set(),
      pathPatterns: new Set(),
      tableSignature: new Set()
    };
  }
  return GLOBAL_BASE[name];
}

async function sourcePreloaded() {
  console.log("Loading SOURCE 2: App preloaded patterns...");
  const preloaded: Record<string, any> = {
    "imessage": { appName: "iMessage", pathPatterns: ["**/Messages/chat.db"], tableSignature: ["message","chat","handle","attachment"], epochConversion: "+978307200", readStrategy: "sqlite_temp_copy" },
    "apple_notes": { appName: "Apple Notes", pathPatterns: ["**/group.com.apple.notes/NoteStore.sqlite"], tableSignature: ["ZNOTE","ZNOTEBODY","ZACCOUNT"] },
    "whatsapp": { appName: "WhatsApp", pathPatterns: ["**/group.net.whatsapp.whatsapp.shared/**"], tableSignature: ["ZWAMESSAGE","ZWAADDRESSBOOKCONTACT"] },
    "signal": { appName: "Signal", pathPatterns: ["**/Signal/sql/db.sqlite"], tableSignature: ["messages","conversations","contacts"] },
    "calendar": { appName: "Apple Calendar", pathPatterns: ["**/Calendars/**/*.sqlite","**/Calendar Cache"], tableSignature: ["ZCALENDARITEM","ZCALENDAR","ZPARTICIPANT"], epochConversion: "+978307200" },
    "contacts": { appName: "Apple Contacts", pathPatterns: ["**/AddressBook/**/*.abcddb"], tableSignature: ["ZABCDRECORD","ZABCDEMAILADDRESS","ZABCDPHONENUMBER"] },
    "reminders": { appName: "Apple Reminders", pathPatterns: ["**/group.com.apple.reminders/**/*.sqlite"], tableSignature: ["ZREMCDREMINDER","ZREMCDOBJECT"] },
    "safari": { appName: "Safari", pathPatterns: ["**/Safari/History.db"], tableSignature: ["history_items","history_visits"], epochConversion: "+978307200" },
    "chrome": { appName: "Google Chrome", pathPatterns: ["**/Chrome/*/History","**/Chrome/Default/History"], tableSignature: ["urls","visits","keyword_search_terms"], epochConversion: "(ts/1000000)-11644473600" },
    "spotify": { appName: "Spotify", pathPatterns: ["**/Spotify/*.db"], tableSignature: ["track_cache","playlist_cache","play_history"] },
    "podcasts": { appName: "Apple Podcasts", pathPatterns: ["**/group.com.apple.podcasts/**/*.sqlite"], tableSignature: ["ZMTEPISODE","ZMTCHANNEL","ZMTCATEGORY"] },
    "telegram": { appName: "Telegram", pathPatterns: ["**/group.net.telegram.TelegramShared/**"], tableSignature: ["TMessage","TConversation","TUser"] },
    "discord": { appName: "Discord", pathPatterns: ["**/discord/**/*.db"], readStrategy: "leveldb" },
    "apple_mail": { appName: "Apple Mail", pathPatterns: ["**/Mail/**/*.emlx"], readStrategy: "emlx_parser" },
    "facetime": { appName: "FaceTime", pathPatterns: ["**/Application Support/FaceTime/**/*.db"], tableSignature: ["ZCALLRECORD","ZPARTICIPANT"] },
    "maps": { appName: "Apple Maps", pathPatterns: ["**/Application Support/Maps/**/*.db"], tableSignature: ["history","search","favorite"] },
    "journal": { appName: "Apple Journal", pathPatterns: ["**/group.com.apple.journal/**/*.sqlite"], tableSignature: [] }
  };

  for (const v of Object.values(preloaded)) {
    const app = getApp(v.appName);
    app.sources.add("preloaded");
    if (v.pathPatterns) v.pathPatterns.forEach((p: string) => app.pathPatterns.add(p));
    if (v.tableSignature) v.tableSignature.forEach((p: string) => app.tableSignature.add(p));
    if (v.epochConversion) app.epochConversion = v.epochConversion;
    if (v.readStrategy) app.readStrategy = v.readStrategy;
  }
}

async function sourceGitHub() {
  console.log("Loading SOURCE 1: GitHub Repos...");
  const REPOS = [
    "nicholasgasior/signal-export",
    "KnugiHK/WhatsApp-Chat-Exporter",
    "obsidianforensics/hindsight",
    "richinfante/iphonebackuptools",
    "madebyak/iphone-backup-decrypt",
    "thephw/apple-notes-liberator",
    "gauthierm/mac-sqlite",
    "libimobiledevice/libimobiledevice"
  ];

  for (const repo of REPOS) {
    try {
      const headers: HeadersInit = GITHUB_TOKEN ? { "Authorization": `Bearer ${GITHUB_TOKEN}` } : {};
      const res = await fetch(`https://api.github.com/repos/${repo}/git/trees/HEAD?recursive=1`, { headers });
      if (!res.ok) continue;
      const data = await res.json() as any;
      const files = (data.tree || []).filter((f: any) => /\.(py|js|ts|md|sql)$/.test(f.path));
      
      const appName = repo.split("/")[1].replace(/-/g, " ");
      const app = getApp(appName);
      app.sources.add("github");

      // We just do a sample analysis on the names for now to avoid hammering API
      for (const file of files) {
         if (file.path.includes("Message")) app.tableSignature.add("message");
         if (file.path.includes("history")) app.tableSignature.add("history_items");
         if (file.path.includes("whatsapp")) app.tableSignature.add("ZWAMESSAGE");
      }
    } catch { continue; }
  }
}

async function sourceHomebrew() {
  console.log("Loading SOURCE 3: Homebrew path mapper...");
  try {
    const out = fs.readFileSync("/tmp/brew.json", "utf-8");
    const data = JSON.parse(out);
    for (const cask of data.casks || []) {
      const name = cask.name?.[0] || cask.token;
      const app = getApp(name);
      app.sources.add("homebrew");
      app.pathPatterns.add(`**/Application Support/${name}/**`);
      app.pathPatterns.add(`**/${name}/**/*.sqlite`);
    }
  } catch (e) {
    console.log("Homebrew source skipped (error or no brew).");
  }
}

async function sourceStackOverflow() {
  console.log("Loading SOURCE 4: StackOverflow API...");
  const queries = ["iMessage sqlite schema", "WhatsApp database tables mac", "Signal database sqlite", "macOS app sqlite location", "iOS backup sqlite tables"];
  for (const q of queries) {
    try {
      const res = await fetch(`https://api.stackexchange.com/2.3/search?order=desc&sort=votes&intitle=${encodeURIComponent(q)}&site=stackoverflow&filter=withbody`);
      if (!res.ok) continue;
      const data = await res.json() as any;
      const appName = q.split(" ")[0];
      const app = getApp(appName);
      app.sources.add("stackoverflow");
      
      for (const item of (data.items || [])) {
        const body = item.body || "";
        const matches = Array.from(body.matchAll(/\b([A-Z][A-Z_]{2,})\b/g));
        matches.forEach((m: any) => app.tableSignature.add(m[1]));
      }
    } catch { continue; }
  }
}

async function sourceHuggingFace() {
  console.log("Loading SOURCE 5: HuggingFace datasets...");
  try {
    const res = await fetch("https://huggingface.co/api/datasets?search=sqlite+schema&limit=20");
    if (!res.ok) return;
    const data = await res.json() as any[];
    for (const dataset of data) {
      const name = dataset.id.split("/").pop();
      const app = getApp(name);
      app.sources.add("huggingface");
      app.tableSignature.add(name); // Very generic extraction
    }
  } catch { return; }
}

async function sourceAppleDocs() {
  console.log("Loading SOURCE 6: Apple Docs...");
  const pages = ["eventkit", "contacts", "messages"];
  for (const p of pages) {
    try {
      const res = await fetch(`https://developer.apple.com/documentation/${p}`);
      if (!res.ok) continue;
      const text = await res.text();
      const app = getApp("Apple " + p.charAt(0).toUpperCase() + p.slice(1));
      app.sources.add("apple_docs");
      
      const cnMatches = Array.from(text.matchAll(/\b(CN[A-Za-z]+)\b/g));
      cnMatches.forEach(m => app.tableSignature.add("Z" + m[1].toUpperCase().replace("CN","")));
    } catch { continue; }
  }
}

async function run() {
  await sourcePreloaded();
  await sourceGitHub();
  await sourceHomebrew();
  await sourceStackOverflow();
  await sourceHuggingFace();
  await sourceAppleDocs();

  console.log("\nMerging sources...");
  
  let data: any = { version: "2.0", lastUpdated: new Date().toISOString(), apps: [], learned: {} };
  if (fs.existsSync(KNOWLEDGE_FILE)) {
    try { data = JSON.parse(fs.readFileSync(KNOWLEDGE_FILE, "utf-8")); } catch {}
  }
  
  if (!data.apps) data.apps = [];

  const sourceCounts: Record<string, number> = {};

  for (const app of Object.values(GLOBAL_BASE)) {
     const count = app.sources.size;
     let confidence = 0.5;
     if (count >= 3) confidence = 1.0;
     else if (count === 2) confidence = 0.9;
     else if (count === 1) confidence = 0.8;

     let sourceName = Array.from(app.sources)[0] || "unknown";
     if (app.sources.has("preloaded")) sourceName = "preloaded";

     sourceCounts[sourceName] = (sourceCounts[sourceName] || 0) + 1;

     const entry = {
       name: app.appName,
       category: app.category || "other",
       schema: Object.fromEntries(Array.from(app.tableSignature).map(t => [t, []])),
       confidence,
       source: sourceName,
       pathPatterns: Array.from(app.pathPatterns)
     };

     const existingIdx = data.apps.findIndex((a: any) => a.name === app.appName);
     if (existingIdx >= 0) {
       data.apps[existingIdx] = { ...data.apps[existingIdx], ...entry };
     } else {
       data.apps.push(entry);
     }
  }

  data.apps.sort((a: any, b: any) => b.confidence - a.confidence);

  fs.writeFileSync(KNOWLEDGE_FILE, JSON.stringify(data, null, 2), "utf-8");

  console.log(`\nLoaded ${sourceCounts["preloaded"] || 0} apps from preloaded`);
  console.log(`Loaded ${sourceCounts["github"] || 0} apps from github`);
  console.log(`Loaded ${sourceCounts["homebrew"] || 0} apps from homebrew`);
  console.log(`Loaded ${sourceCounts["stackoverflow"] || 0} apps from stackoverflow`);
  console.log(`Loaded ${sourceCounts["huggingface"] || 0} apps from huggingface`);
  console.log(`Loaded ${sourceCounts["apple_docs"] || 0} apps from apple_docs`);
  console.log(`\nTotal: ${data.apps.length} apps in brain static base.`);
  console.log("Claude will only be called for unknowns.");
}

run().catch(console.error);
