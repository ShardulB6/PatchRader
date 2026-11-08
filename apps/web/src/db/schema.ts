import { boolean, date, doublePrecision, pgTable, primaryKey, text } from "drizzle-orm/pg-core";

// Mirrors scripts/setup-db.sql, which also makes this table a hypertable.
// The two sources cover different CVEs: "signals" rows (2024-2025) cover all CVEs
// with data that month, and "scoreboard" rows (2026) only cover benchmark CVEs, once
// each. Filter on source for "latest month" queries, or they only see recent CVEs.
export const exploitSignals = pgTable(
  "exploit_signals",
  {
    month: date("month").notNull(),
    cveId: text("cve_id").notNull(),
    epss: doublePrecision("epss"),
    inKev: boolean("in_kev").notNull(),
    exploitdb: boolean("exploitdb").notNull(),
    metasploit: boolean("metasploit").notNull(),
    nuclei: boolean("nuclei").notNull(),
    pocGithub: boolean("poc_github").notNull(),
    source: text("source", { enum: ["signals", "scoreboard"] }).notNull(),
  },
  (table) => [primaryKey({ columns: [table.month, table.cveId] })],
);
