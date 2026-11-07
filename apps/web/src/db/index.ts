import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import { ENV } from "@/env.server";

import { poolConfig } from "./connection";
import * as schema from "./schema";

function createDb() {
  if (!ENV.DATABASE_URL) {
    throw new Error("DATABASE_URL is not set. See the Database section of the README.");
  }
  const pool = new Pool(poolConfig(ENV.DATABASE_URL));
  // pg emits this when an idle connection drops, and an unhandled emit kills the
  // process. The pool opens a new connection for the next query.
  pool.on("error", (error) => {
    console.error("Idle database connection failed:", error.message);
  });
  return drizzle(pool, { schema });
}

let db: ReturnType<typeof createDb> | undefined;

// Connects on first use, so the app still builds and runs without a database.
export function getDb() {
  db ??= createDb();
  return db;
}
