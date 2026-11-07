// Replaces exploit_signals with the monthly signals and the 2026 scoreboard values.
// Usage, from apps/web: pnpm run db:load [path to data directory]
import { createReadStream, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createInterface } from "node:readline";

import pg from "pg";
import { from as copyFrom } from "pg-copy-streams";

import { poolConfig } from "../src/db/connection.ts";

const SOURCES = [
  { file: "exploit_signals_2024.csv", source: "signals" },
  { file: "exploit_signals_2025.csv", source: "signals" },
  { file: "scoreboard_2026.csv", source: "scoreboard" },
] as const;

const COPY_SQL = `COPY exploit_signals
  (month, cve_id, epss, in_kev, exploitdb, metasploit, nuclei, poc_github, source)
  FROM STDIN WITH (FORMAT csv, NULL '')`;

const monthEnds = new Map<string, string>();

function monthEnd(month: string): string {
  let end = monthEnds.get(month);
  if (!end) {
    const [year, monthNumber] = month.split("-").map(Number);
    end = new Date(Date.UTC(year!, monthNumber!, 0)).toISOString().slice(0, 10);
    monthEnds.set(month, end);
  }
  return end;
}

// These files only hold IDs, numbers and flags, so no field is ever quoted.
async function* copyRows(path: string, source: "signals" | "scoreboard") {
  let header: string[] | undefined;
  for await (const line of createInterface({ input: createReadStream(path) })) {
    if (!line) continue;
    const fields = line.split(",");
    if (!header) {
      header = fields;
      continue;
    }
    const value = (name: string) => fields[header!.indexOf(name)];
    // The scoreboard only lists vulnerabilities that were not yet on the KEV list.
    const inKev = source === "signals" ? value("in_kev") : "0";
    const month = source === "signals" ? value("month")! : value("snapshot_month")!;
    yield (
      [
        monthEnd(month),
        value("cve_id"),
        value("epss"),
        inKev,
        value("exploitdb"),
        value("metasploit"),
        value("nuclei"),
        value("poc_github"),
        source,
      ].join(",") + "\n"
    );
  }
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is not set.");
  const dataDir = resolve(process.argv[2] ?? "../../data");

  const client = new pg.Client(poolConfig(databaseUrl));
  await client.connect();
  try {
    await client.query(readFileSync(new URL("./setup-db.sql", import.meta.url), "utf8"));

    await client.query("BEGIN");
    await client.query("TRUNCATE exploit_signals");
    for (const { file, source } of SOURCES) {
      console.log(`Loading ${file}...`);
      await pipeline(
        Readable.from(copyRows(resolve(dataDir, file), source)),
        client.query(copyFrom(COPY_SQL)),
      );
    }
    await client.query("COMMIT");

    console.log("Compressing chunks...");
    const { rows } = await client.query<{ chunk: string }>(
      "SELECT show_chunks('exploit_signals')::text AS chunk",
    );
    for (const { chunk } of rows) {
      await client.query(`CALL convert_to_columnstore('${chunk}')`);
    }

    const { rows: counts } = await client.query(
      "SELECT source, count(*)::int AS rows FROM exploit_signals GROUP BY source ORDER BY source",
    );
    console.log(counts);
  } finally {
    await client.end();
  }
}

await main();
