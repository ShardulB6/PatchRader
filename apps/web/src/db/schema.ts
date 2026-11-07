import { boolean, date, doublePrecision, pgTable, primaryKey, text } from "drizzle-orm/pg-core";

// Mirrors scripts/setup-db.sql, which also makes this table a hypertable.
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
