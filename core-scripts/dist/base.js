/**
 * LDP Connectors — base class for building your own connector.
 *
 * @example
 * ```ts
 * import { BaseConnector, ConnectorDescriptor } from "@ldp-protocol/sdk/connectors";
 *
 * export class MyAppConnector implements BaseConnector {
 *   descriptor: ConnectorDescriptor = {
 *     name: "myapp", app: "My App", version: "1.0",
 *     dataPaths: ["~/.myapp/data.db"],
 *     permissions: ["data.read"],
 *     namedQueries: { recent: "Most recent records" },
 *     description: "My app local database",
 *   };
 *
 *   async discover() { return existsSync(expandHome("~/.myapp/data.db")); }
 *   async schema()   { return { records: { id: "row id", value: "data" } }; }
 *   async read(query, limit = 500) {
 *     // your SQLite / JSON / CSV reading logic
 *     return [];
 *   }
 * }
 * ```
 */
import * as os from "node:os";
import * as fs from "node:fs";
import * as path from "node:path";
/** Expand ~ to home directory. */
export function expandHome(p) {
    return p.replace(/^~/, os.homedir());
}
/** Find the first path in a list that exists (supports glob * patterns). */
export function findFirst(paths) {
    for (const p of paths) {
        const expanded = expandHome(p);
        if (expanded.includes("*")) {
            const dir = path.dirname(expanded);
            const name = path.basename(expanded);
            if (!fs.existsSync(dir))
                continue;
            const regex = new RegExp("^" + name.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$");
            const match = fs.readdirSync(dir).find(f => regex.test(f));
            if (match)
                return path.join(dir, match);
        }
        else if (fs.existsSync(expanded)) {
            return expanded;
        }
    }
    return null;
}
