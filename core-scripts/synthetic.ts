/**
 * LDP Synthetic Connectors
 * Spotify, Banking, Files, WhatsApp — all with realistic fake data.
 * Use for development and testing without real apps installed.
 */

import type { BaseConnector, ConnectorDescriptor, Row, SchemaMap } from "./types.js";

// ── Spotify ───────────────────────────────────────────────────────────────────

export class SyntheticSpotifyConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name: "spotify", app: "Spotify", version: "1.0",
    dataPaths: ["synthetic"], permissions: ["history.read"],
    namedQueries: { focus_music: "Music played during work hours" },
    description: "Spotify listening history — local cache.",
  };

  private readonly tracks = [
    { track: "Lofi Hip Hop Radio", artist: "ChilledCow",   plays: 340, focus: true  },
    { track: "Focus Flow",         artist: "Spotify",      plays: 280, focus: true  },
    { track: "Blinding Lights",    artist: "The Weeknd",   plays: 150, focus: false },
    { track: "Anti-Hero",          artist: "Taylor Swift", plays: 120, focus: false },
    { track: "Calm Piano",         artist: "Relaxing",     plays: 200, focus: true  },
    { track: "Deep Work Mix",      artist: "Brain.fm",     plays: 180, focus: true  },
    { track: "Study Beats",        artist: "Various",      plays: 220, focus: true  },
  ];

  async discover(): Promise<boolean> { return true; }
  async schema():   Promise<SchemaMap> {
    return { tracks: { track_name: "title", artist_name: "artist",
                       ms_played: "milliseconds played", skipped: "was skipped" } };
  }

  async read(query: string, limit = 500): Promise<Row[]> {
    const q = query.toLowerCase();
    let rows: Row[] = this.tracks.map(t => ({ ...t, _recency: Math.random() * 0.7 + 0.3 }));
    if (/focus|work|study/.test(q)) rows = rows.filter(r => r.focus);
    return rows.sort((a, b) => (b.plays as number) - (a.plays as number)).slice(0, limit);
  }
}

// ── Banking ───────────────────────────────────────────────────────────────────

const MERCHANTS = [
  ["Tesco",        "groceries",     85  ],
  ["Amazon",       "shopping",      120 ],
  ["Spotify",      "subscriptions", 10  ],
  ["Netflix",      "subscriptions", 15  ],
  ["Zomato",       "food_delivery", 65  ],
  ["Uber",         "transport",     45  ],
  ["Gym",          "health",        40  ],
  ["Electricity",  "utilities",     90  ],
  ["Rent",         "housing",       800 ],
  ["Salary",       "income",        3500],
  ["Coffee Shop",  "food",          35  ],
  ["Insurance",    "subscriptions", 55  ],
] as const;

export class SyntheticBankingConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name: "banking", app: "Bank Statements (CSV/PDF)", version: "1.0",
    dataPaths: ["~/Downloads/*.csv", "~/Documents/*statement*.pdf"],
    permissions: ["transactions.read"],
    namedQueries: {
      spending_summary: "Where am I spending most money?",
      savings_rate:     "What is my savings rate?",
      recent:           "Recent transactions",
    },
    description: "Bank statement exports — AI financial advice that never leaves your device.",
  };

  private readonly txns: Row[];

  constructor() {
    const now = Date.now() / 1000;
    this.txns = [];
    for (let i = 0; i < 90; i++) {
      const dayTs = now - (89 - i) * 86400;
      const count = Math.floor(Math.random() * 4) + 1;
      for (let j = 0; j < count; j++) {
        const [merchant, cat, avg] = MERCHANTS[Math.floor(Math.random() * MERCHANTS.length)];
        this.txns.push({
          date:     new Date(dayTs * 1000).toISOString().slice(0, 10),
          merchant, category: cat,
          amount:   Math.round(avg * (0.7 + Math.random() * 0.6) * 100) / 100,
          type:     cat === "income" ? "credit" : "debit",
          _recency: Math.max(0, 1 - (89 - i) / 90),
        });
      }
    }
  }

  async discover(): Promise<boolean> { return true; }
  async schema():   Promise<SchemaMap> {
    return { transactions: { date: "YYYY-MM-DD", merchant: "payee name",
                              category: "spending category",
                              amount: "amount in local currency",
                              type: "credit (in) or debit (out)" } };
  }

  async read(query: string, limit = 500): Promise<Row[]> {
    const q = query.toLowerCase();

    if (/spend|where|wasting|expensive|most/.test(q)) {
      const cats: Record<string, number> = {};
      for (const t of this.txns)
        if (t.type === "debit")
          cats[t.category as string] = (cats[t.category as string] ?? 0) + (t.amount as number);
      return Object.entries(cats)
        .sort(([, a], [, b]) => b - a)
        .map(([category, total]) => ({ category, total_spent: Math.round(total * 100) / 100, _recency: 0.8 }))
        .slice(0, limit);
    }

    if (/afford|save|savings|budget/.test(q)) {
      const inc = this.txns.filter(t => t.type === "credit").reduce((s, t) => s + (t.amount as number), 0);
      const exp = this.txns.filter(t => t.type === "debit" ).reduce((s, t) => s + (t.amount as number), 0);
      return [{
        summary:          "3-month financial snapshot",
        total_income:     Math.round(inc),
        total_expenses:   Math.round(exp),
        net_savings:      Math.round(inc - exp),
        savings_rate_pct: Math.round((inc - exp) / inc * 1000) / 10,
        _recency: 1,
      }];
    }

    return [...this.txns]
      .sort((a, b) => String(b.date) > String(a.date) ? 1 : -1)
      .slice(0, limit);
  }
}

// ── Files ─────────────────────────────────────────────────────────────────────

export class SyntheticFilesConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name: "files", app: "Local Documents", version: "1.0",
    dataPaths: ["~/Documents", "~/Downloads", "~/Desktop"],
    permissions: ["files.read"],
    namedQueries: { contracts: "Legal contracts", payslips: "Salary documents" },
    description: "PDFs and documents — AI review without uploading.",
  };

  private readonly docs = [
    { filename: "Employment_Contract_2024.pdf",  type: "contract",
      content: "Position: Senior Developer. Salary: £85,000. Notice: 3 months. Non-compete: 12 months." },
    { filename: "Tenancy_Agreement_2024.pdf",     type: "contract",
      content: "Monthly rent: £1,200. Deposit: £2,400. Break clause: 6 months. No pets." },
    { filename: "Salary_Slip_March_2026.pdf",     type: "payslip",
      content: "Gross: £7,083. Tax: £1,680. NI: £520. Net: £4,883." },
    { filename: "Medical_Report_2025.pdf",        type: "health",
      content: "BP: 120/80. Cholesterol: 4.2. BMI: 23.5. Maintain current exercise." },
    { filename: "NDA_Contractor_2025.pdf",        type: "contract",
      content: "Confidentiality: 5 years. Jurisdiction: England. Damages: £50,000 per breach." },
    { filename: "Bank_Statement_Feb_2026.pdf",    type: "finance",
      content: "Opening: £4,230. Closing: £3,890. Credits: £7,083. Debits: £7,423." },
  ];

  async discover(): Promise<boolean> { return true; }
  async schema():   Promise<SchemaMap> {
    return { documents: { filename: "file name", type: "document category",
                           content: "extracted text" } };
  }

  async read(query: string, limit = 500): Promise<Row[]> {
    const q = query.toLowerCase();
    let rows: Row[] = this.docs.map(d => ({ ...d, _recency: 0.8 }));
    if (/contract|legal|nda|clause/.test(q)) rows = rows.filter(r => r.type === "contract");
    else if (/salary|pay|payslip/.test(q))   rows = rows.filter(r => ["payslip","finance"].includes(r.type as string));
    else if (/health|medical/.test(q))        rows = rows.filter(r => r.type === "health");
    return rows.slice(0, limit);
  }
}

// ── WhatsApp ──────────────────────────────────────────────────────────────────

export class SyntheticWhatsAppConnector implements BaseConnector {
  readonly descriptor: ConnectorDescriptor = {
    name: "whatsapp", app: "WhatsApp", version: "1.0",
    dataPaths: ["~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite"],
    permissions: ["messages.read"],
    namedQueries: { top_contacts: "People I message most" },
    description: "WhatsApp message patterns.",
  };

  private readonly contacts = [
    "Mum", "Dad", "Best Friend", "Partner", "Work Colleague",
    "Study Group", "Family Chat", "Project Team", "Mentor",
  ];

  async discover(): Promise<boolean> { return true; }
  async schema():   Promise<SchemaMap> {
    return { messages: { contact: "contact name", message_count: "total messages",
                          last_message: "last message date",
                          initiated_by: "who starts conversations" } };
  }

  async read(query: string, limit = 500): Promise<Row[]> {
    const now = Date.now() / 1000;
    const rows: Row[] = this.contacts.map(contact => ({
      contact,
      message_count: Math.floor(Math.random() * 490 + 10),
      last_message:  new Date((now - Math.random() * 30 * 86400) * 1000).toISOString().slice(0, 10),
      initiated_by:  ["you", "them", "equal"][Math.floor(Math.random() * 3)],
      _recency:      Math.random() * 0.8 + 0.2,
    }));
    return rows.sort((a, b) => (b.message_count as number) - (a.message_count as number)).slice(0, limit);
  }
}

// ── Register helper ───────────────────────────────────────────────────────────

import type { LDPEngine } from "./engine.js";

export function registerAllSynthetic(engine: LDPEngine): void {
  engine.register(new SyntheticSpotifyConnector());
  engine.register(new SyntheticBankingConnector());
  engine.register(new SyntheticFilesConnector());
  engine.register(new SyntheticWhatsAppConnector());
}
