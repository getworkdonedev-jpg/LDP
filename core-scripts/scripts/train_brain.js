"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var fs = require("fs");
var path = require("path");
var os = require("os");
var child_process_1 = require("child_process");
var KNOWLEDGE_FILE = path.join(os.homedir(), "Desktop", "LDP", "core-scripts", "brain_knowledge.json");
var GITHUB_TOKEN = process.env.GITHUB_TOKEN;
var GLOBAL_BASE = {};
function getApp(name) {
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
function sourcePreloaded() {
    return __awaiter(this, void 0, void 0, function () {
        var preloaded, _loop_1, _i, _a, v;
        return __generator(this, function (_b) {
            console.log("Loading SOURCE 2: App preloaded patterns...");
            preloaded = {
                "imessage": { appName: "iMessage", pathPatterns: ["**/Messages/chat.db"], tableSignature: ["message", "chat", "handle", "attachment"], epochConversion: "+978307200", readStrategy: "sqlite_temp_copy" },
                "apple_notes": { appName: "Apple Notes", pathPatterns: ["**/group.com.apple.notes/NoteStore.sqlite"], tableSignature: ["ZNOTE", "ZNOTEBODY", "ZACCOUNT"] },
                "whatsapp": { appName: "WhatsApp", pathPatterns: ["**/group.net.whatsapp.whatsapp.shared/**"], tableSignature: ["ZWAMESSAGE", "ZWAADDRESSBOOKCONTACT"] },
                "signal": { appName: "Signal", pathPatterns: ["**/Signal/sql/db.sqlite"], tableSignature: ["messages", "conversations", "contacts"] },
                "calendar": { appName: "Apple Calendar", pathPatterns: ["**/Calendars/**/*.sqlite", "**/Calendar Cache"], tableSignature: ["ZCALENDARITEM", "ZCALENDAR", "ZPARTICIPANT"], epochConversion: "+978307200" },
                "contacts": { appName: "Apple Contacts", pathPatterns: ["**/AddressBook/**/*.abcddb"], tableSignature: ["ZABCDRECORD", "ZABCDEMAILADDRESS", "ZABCDPHONENUMBER"] },
                "reminders": { appName: "Apple Reminders", pathPatterns: ["**/group.com.apple.reminders/**/*.sqlite"], tableSignature: ["ZREMCDREMINDER", "ZREMCDOBJECT"] },
                "safari": { appName: "Safari", pathPatterns: ["**/Safari/History.db"], tableSignature: ["history_items", "history_visits"], epochConversion: "+978307200" },
                "chrome": { appName: "Google Chrome", pathPatterns: ["**/Chrome/*/History", "**/Chrome/Default/History"], tableSignature: ["urls", "visits", "keyword_search_terms"], epochConversion: "(ts/1000000)-11644473600" },
                "spotify": { appName: "Spotify", pathPatterns: ["**/Spotify/*.db"], tableSignature: ["track_cache", "playlist_cache", "play_history"] },
                "podcasts": { appName: "Apple Podcasts", pathPatterns: ["**/group.com.apple.podcasts/**/*.sqlite"], tableSignature: ["ZMTEPISODE", "ZMTCHANNEL", "ZMTCATEGORY"] },
                "telegram": { appName: "Telegram", pathPatterns: ["**/group.net.telegram.TelegramShared/**"], tableSignature: ["TMessage", "TConversation", "TUser"] },
                "discord": { appName: "Discord", pathPatterns: ["**/discord/**/*.db"], readStrategy: "leveldb" },
                "apple_mail": { appName: "Apple Mail", pathPatterns: ["**/Mail/**/*.emlx"], readStrategy: "emlx_parser" },
                "facetime": { appName: "FaceTime", pathPatterns: ["**/Application Support/FaceTime/**/*.db"], tableSignature: ["ZCALLRECORD", "ZPARTICIPANT"] },
                "maps": { appName: "Apple Maps", pathPatterns: ["**/Application Support/Maps/**/*.db"], tableSignature: ["history", "search", "favorite"] },
                "journal": { appName: "Apple Journal", pathPatterns: ["**/group.com.apple.journal/**/*.sqlite"], tableSignature: [] }
            };
            _loop_1 = function (v) {
                var app = getApp(v.appName);
                app.sources.add("preloaded");
                if (v.pathPatterns)
                    v.pathPatterns.forEach(function (p) { return app.pathPatterns.add(p); });
                if (v.tableSignature)
                    v.tableSignature.forEach(function (p) { return app.tableSignature.add(p); });
                if (v.epochConversion)
                    app.epochConversion = v.epochConversion;
                if (v.readStrategy)
                    app.readStrategy = v.readStrategy;
            };
            for (_i = 0, _a = Object.values(preloaded); _i < _a.length; _i++) {
                v = _a[_i];
                _loop_1(v);
            }
            return [2 /*return*/];
        });
    });
}
function sourceGitHub() {
    return __awaiter(this, void 0, void 0, function () {
        var REPOS, _i, REPOS_1, repo, headers, res, data, files, appName, app, _a, files_1, file, _b;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    console.log("Loading SOURCE 1: GitHub Repos...");
                    REPOS = [
                        "nicholasgasior/signal-export",
                        "KnugiHK/WhatsApp-Chat-Exporter",
                        "obsidianforensics/hindsight",
                        "richinfante/iphonebackuptools",
                        "madebyak/iphone-backup-decrypt",
                        "thephw/apple-notes-liberator",
                        "gauthierm/mac-sqlite",
                        "libimobiledevice/libimobiledevice"
                    ];
                    _i = 0, REPOS_1 = REPOS;
                    _c.label = 1;
                case 1:
                    if (!(_i < REPOS_1.length)) return [3 /*break*/, 7];
                    repo = REPOS_1[_i];
                    _c.label = 2;
                case 2:
                    _c.trys.push([2, 5, , 6]);
                    headers = GITHUB_TOKEN ? { "Authorization": "Bearer ".concat(GITHUB_TOKEN) } : {};
                    return [4 /*yield*/, fetch("https://api.github.com/repos/".concat(repo, "/git/trees/HEAD?recursive=1"), { headers: headers })];
                case 3:
                    res = _c.sent();
                    if (!res.ok)
                        return [3 /*break*/, 6];
                    return [4 /*yield*/, res.json()];
                case 4:
                    data = _c.sent();
                    files = (data.tree || []).filter(function (f) { return /\.(py|js|ts|md|sql)$/.test(f.path); });
                    appName = repo.split("/")[1].replace(/-/g, " ");
                    app = getApp(appName);
                    app.sources.add("github");
                    // We just do a sample analysis on the names for now to avoid hammering API
                    for (_a = 0, files_1 = files; _a < files_1.length; _a++) {
                        file = files_1[_a];
                        if (file.path.includes("Message"))
                            app.tableSignature.add("message");
                        if (file.path.includes("history"))
                            app.tableSignature.add("history_items");
                        if (file.path.includes("whatsapp"))
                            app.tableSignature.add("ZWAMESSAGE");
                    }
                    return [3 /*break*/, 6];
                case 5:
                    _b = _c.sent();
                    return [3 /*break*/, 6];
                case 6:
                    _i++;
                    return [3 /*break*/, 1];
                case 7: return [2 /*return*/];
            }
        });
    });
}
function sourceHomebrew() {
    return __awaiter(this, void 0, void 0, function () {
        var out, data, _i, _a, cask, name_1, app;
        var _b;
        return __generator(this, function (_c) {
            console.log("Loading SOURCE 3: Homebrew path mapper...");
            try {
                out = (0, child_process_1.execSync)("/opt/homebrew/bin/brew info --json=v2 --all-casks", { maxBuffer: 10 * 1024 * 1024, encoding: 'utf-8' });
                data = JSON.parse(out);
                for (_i = 0, _a = data.casks || []; _i < _a.length; _i++) {
                    cask = _a[_i];
                    name_1 = ((_b = cask.name) === null || _b === void 0 ? void 0 : _b[0]) || cask.token;
                    app = getApp(name_1);
                    app.sources.add("homebrew");
                    app.pathPatterns.add("**/Application Support/".concat(name_1, "/**"));
                    app.pathPatterns.add("**/".concat(name_1, "/**/*.sqlite"));
                }
            }
            catch (e) {
                console.log("Homebrew source skipped (error or no brew).");
            }
            return [2 /*return*/];
        });
    });
}
function sourceStackOverflow() {
    return __awaiter(this, void 0, void 0, function () {
        var queries, _loop_2, _i, queries_1, q;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Loading SOURCE 4: StackOverflow API...");
                    queries = ["iMessage sqlite schema", "WhatsApp database tables mac", "Signal database sqlite", "macOS app sqlite location", "iOS backup sqlite tables"];
                    _loop_2 = function (q) {
                        var res, data, appName, app_1, _b, _c, item, body, matches, _d;
                        return __generator(this, function (_e) {
                            switch (_e.label) {
                                case 0:
                                    _e.trys.push([0, 3, , 4]);
                                    return [4 /*yield*/, fetch("https://api.stackexchange.com/2.3/search?order=desc&sort=votes&intitle=".concat(encodeURIComponent(q), "&site=stackoverflow&filter=withbody"))];
                                case 1:
                                    res = _e.sent();
                                    if (!res.ok)
                                        return [2 /*return*/, "continue"];
                                    return [4 /*yield*/, res.json()];
                                case 2:
                                    data = _e.sent();
                                    appName = q.split(" ")[0];
                                    app_1 = getApp(appName);
                                    app_1.sources.add("stackoverflow");
                                    for (_b = 0, _c = (data.items || []); _b < _c.length; _b++) {
                                        item = _c[_b];
                                        body = item.body || "";
                                        matches = Array.from(body.matchAll(/\b([A-Z][A-Z_]{2,})\b/g));
                                        matches.forEach(function (m) { return app_1.tableSignature.add(m[1]); });
                                    }
                                    return [3 /*break*/, 4];
                                case 3:
                                    _d = _e.sent();
                                    return [2 /*return*/, "continue"];
                                case 4: return [2 /*return*/];
                            }
                        });
                    };
                    _i = 0, queries_1 = queries;
                    _a.label = 1;
                case 1:
                    if (!(_i < queries_1.length)) return [3 /*break*/, 4];
                    q = queries_1[_i];
                    return [5 /*yield**/, _loop_2(q)];
                case 2:
                    _a.sent();
                    _a.label = 3;
                case 3:
                    _i++;
                    return [3 /*break*/, 1];
                case 4: return [2 /*return*/];
            }
        });
    });
}
function sourceHuggingFace() {
    return __awaiter(this, void 0, void 0, function () {
        var res, data, _i, data_1, dataset, name_2, app, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    console.log("Loading SOURCE 5: HuggingFace datasets...");
                    _b.label = 1;
                case 1:
                    _b.trys.push([1, 4, , 5]);
                    return [4 /*yield*/, fetch("https://huggingface.co/api/datasets?search=sqlite+schema&limit=20")];
                case 2:
                    res = _b.sent();
                    if (!res.ok)
                        return [2 /*return*/];
                    return [4 /*yield*/, res.json()];
                case 3:
                    data = _b.sent();
                    for (_i = 0, data_1 = data; _i < data_1.length; _i++) {
                        dataset = data_1[_i];
                        name_2 = dataset.id.split("/").pop();
                        app = getApp(name_2);
                        app.sources.add("huggingface");
                        app.tableSignature.add(name_2); // Very generic extraction
                    }
                    return [3 /*break*/, 5];
                case 4:
                    _a = _b.sent();
                    return [2 /*return*/];
                case 5: return [2 /*return*/];
            }
        });
    });
}
function sourceAppleDocs() {
    return __awaiter(this, void 0, void 0, function () {
        var pages, _loop_3, _i, pages_1, p;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Loading SOURCE 6: Apple Docs...");
                    pages = ["eventkit", "contacts", "messages"];
                    _loop_3 = function (p) {
                        var res, text, app_2, cnMatches, _b;
                        return __generator(this, function (_c) {
                            switch (_c.label) {
                                case 0:
                                    _c.trys.push([0, 3, , 4]);
                                    return [4 /*yield*/, fetch("https://developer.apple.com/documentation/".concat(p))];
                                case 1:
                                    res = _c.sent();
                                    if (!res.ok)
                                        return [2 /*return*/, "continue"];
                                    return [4 /*yield*/, res.text()];
                                case 2:
                                    text = _c.sent();
                                    app_2 = getApp("Apple " + p.charAt(0).toUpperCase() + p.slice(1));
                                    app_2.sources.add("apple_docs");
                                    cnMatches = Array.from(text.matchAll(/\b(CN[A-Za-z]+)\b/g));
                                    cnMatches.forEach(function (m) { return app_2.tableSignature.add("Z" + m[1].toUpperCase().replace("CN", "")); });
                                    return [3 /*break*/, 4];
                                case 3:
                                    _b = _c.sent();
                                    return [2 /*return*/, "continue"];
                                case 4: return [2 /*return*/];
                            }
                        });
                    };
                    _i = 0, pages_1 = pages;
                    _a.label = 1;
                case 1:
                    if (!(_i < pages_1.length)) return [3 /*break*/, 4];
                    p = pages_1[_i];
                    return [5 /*yield**/, _loop_3(p)];
                case 2:
                    _a.sent();
                    _a.label = 3;
                case 3:
                    _i++;
                    return [3 /*break*/, 1];
                case 4: return [2 /*return*/];
            }
        });
    });
}
function run() {
    return __awaiter(this, void 0, void 0, function () {
        var data, sourceCounts, _loop_4, _i, _a, app;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, sourcePreloaded()];
                case 1:
                    _b.sent();
                    return [4 /*yield*/, sourceGitHub()];
                case 2:
                    _b.sent();
                    return [4 /*yield*/, sourceHomebrew()];
                case 3:
                    _b.sent();
                    return [4 /*yield*/, sourceStackOverflow()];
                case 4:
                    _b.sent();
                    return [4 /*yield*/, sourceHuggingFace()];
                case 5:
                    _b.sent();
                    return [4 /*yield*/, sourceAppleDocs()];
                case 6:
                    _b.sent();
                    console.log("\nMerging sources...");
                    data = { version: "2.0", lastUpdated: new Date().toISOString(), apps: [], learned: {} };
                    if (fs.existsSync(KNOWLEDGE_FILE)) {
                        try {
                            data = JSON.parse(fs.readFileSync(KNOWLEDGE_FILE, "utf-8"));
                        }
                        catch (_c) { }
                    }
                    if (!data.apps)
                        data.apps = [];
                    sourceCounts = {};
                    _loop_4 = function (app) {
                        var count = app.sources.size;
                        var confidence = 0.5;
                        if (count >= 3)
                            confidence = 1.0;
                        else if (count === 2)
                            confidence = 0.9;
                        else if (count === 1)
                            confidence = 0.8;
                        var sourceName = Array.from(app.sources)[0] || "unknown";
                        if (app.sources.has("preloaded"))
                            sourceName = "preloaded";
                        sourceCounts[sourceName] = (sourceCounts[sourceName] || 0) + 1;
                        var entry = {
                            name: app.appName,
                            category: app.category || "other",
                            schema: Object.fromEntries(Array.from(app.tableSignature).map(function (t) { return [t, []]; })),
                            confidence: confidence,
                            source: sourceName,
                            pathPatterns: Array.from(app.pathPatterns)
                        };
                        var existingIdx = data.apps.findIndex(function (a) { return a.name === app.appName; });
                        if (existingIdx >= 0) {
                            data.apps[existingIdx] = __assign(__assign({}, data.apps[existingIdx]), entry);
                        }
                        else {
                            data.apps.push(entry);
                        }
                    };
                    for (_i = 0, _a = Object.values(GLOBAL_BASE); _i < _a.length; _i++) {
                        app = _a[_i];
                        _loop_4(app);
                    }
                    data.apps.sort(function (a, b) { return b.confidence - a.confidence; });
                    fs.writeFileSync(KNOWLEDGE_FILE, JSON.stringify(data, null, 2), "utf-8");
                    console.log("\nLoaded ".concat(sourceCounts["preloaded"] || 0, " apps from preloaded"));
                    console.log("Loaded ".concat(sourceCounts["github"] || 0, " apps from github"));
                    console.log("Loaded ".concat(sourceCounts["homebrew"] || 0, " apps from homebrew"));
                    console.log("Loaded ".concat(sourceCounts["stackoverflow"] || 0, " apps from stackoverflow"));
                    console.log("Loaded ".concat(sourceCounts["huggingface"] || 0, " apps from huggingface"));
                    console.log("Loaded ".concat(sourceCounts["apple_docs"] || 0, " apps from apple_docs"));
                    console.log("\nTotal: ".concat(data.apps.length, " apps in brain static base."));
                    console.log("Claude will only be called for unknowns.");
                    return [2 /*return*/];
            }
        });
    });
}
run().catch(console.error);
