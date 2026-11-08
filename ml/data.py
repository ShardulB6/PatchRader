"""Load the raw CSVs and build the train / validation / scoreboard row sets."""
from __future__ import annotations

from pathlib import Path

import duckdb
import pandas as pd

from . import config

TABLES = ["vulnerabilities", "known_exploited", "exploit_signals_2024", "exploit_signals_2025", "scoreboard_2026"]
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]


def connect(data_dir: Path = config.DATA_DIR, kev_extra: pd.DataFrame | None = None) -> duckdb.DuckDBPyConnection:
    """DuckDB connection with one view per CSV. `kev_extra` appends rows to the KEV list (used only by the
    leakage test that plants fake future KEV entries)."""
    con = duckdb.connect()
    for t in TABLES:
        con.sql(f"""CREATE VIEW "{t}_raw" AS
                    SELECT * FROM read_csv('{data_dir}/{t}.csv', quote='"', escape='"', sample_size=-1)""")
        if t == "known_exploited" and kev_extra is not None:
            con.register("kev_extra_df", kev_extra)
            con.sql(f'CREATE VIEW "{t}" AS SELECT * FROM "{t}_raw" UNION ALL BY NAME SELECT * FROM kev_extra_df')
        else:
            con.sql(f'CREATE VIEW "{t}" AS SELECT * FROM "{t}_raw"')
    return con


def labeled_rows(con: duckdb.DuckDBPyConnection, start: str, end: str, deadline: str, signals: str) -> pd.DataFrame:
    """Rows: published in [start, end] and not on KEV by the end of the publish month.
    Label y = 1 if added to KEV after the publish month and on or before `deadline`.
    Signals come from the publish month, i.e. what was known at the snapshot."""
    flags = ", ".join(f"COALESCE(CAST(s.{f} AS INT), 0) AS {f}" for f in FLAGS)
    return con.sql(f"""
        WITH v AS (SELECT *, CAST(published AS DATE) AS pub FROM vulnerabilities),
             k AS (SELECT cve_id, MIN(CAST(date_added AS DATE)) AS date_added FROM known_exploited GROUP BY cve_id)
        SELECT v.cve_id, v.pub AS published, strftime(v.pub, '%Y-%m') AS snap, v.assigner, v.description,
               CAST(v.cvss3_score AS DOUBLE) AS cvss3_score, v.attack_vector, v.attack_complexity,
               v.privileges_required, v.user_interaction, v.scope, v.cwe_ids,
               CAST(s.epss AS DOUBLE) AS epss, {flags}, k.date_added AS kev_date,
               CAST(k.date_added IS NOT NULL AND k.date_added <= DATE '{deadline}' AS INT) AS y
        FROM v LEFT JOIN k USING (cve_id)
        LEFT JOIN {signals} s ON s.cve_id = v.cve_id AND s.month = strftime(v.pub, '%Y-%m')
        WHERE v.pub BETWEEN DATE '{start}' AND DATE '{end}'
          AND (k.date_added IS NULL OR k.date_added > last_day(v.pub))
        ORDER BY v.cve_id""").df()


def load_splits(con: duckdb.DuckDBPyConnection) -> tuple[pd.DataFrame, pd.DataFrame]:
    """The time-based split: train on 2024, validate on 2025 (rows sorted by cve_id for reproducibility)."""
    return labeled_rows(con, **config.TRAIN_WINDOW), labeled_rows(con, **config.VALID_WINDOW)
