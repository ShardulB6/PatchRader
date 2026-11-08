"""Read-only, predefined vulnerability analytics over local challenge CSVs.

This is the CSV-backed development implementation. It does not connect to
Tiger Cloud; production migration requires the actual database schema.
"""
from pathlib import Path
import os
import tempfile

import duckdb
import pandas as pd

REQUIRED = (
    "vulnerabilities.csv",
    "affected_products.csv",
    "known_exploited.csv",
    "scoreboard_2026.csv",
)
OPTIONAL = (
    "weakness_types.csv",
    "references.csv",
    "exploit_signals_2024.csv",
    "exploit_signals_2025.csv",
)

DATASETS = {
    "vulnerabilities": "vulnerabilities.csv",
    "affected_products": "affected_products.csv",
    "known_exploited": "known_exploited.csv",
    "scoreboard": "scoreboard_2026.csv",
    "weakness_types": "weakness_types.csv",
    # "references" is an SQL keyword, so the table gets a different name.
    "cve_references": "references.csv",
    "signals_2024": "exploit_signals_2024.csv",
    "signals_2025": "exploit_signals_2025.csv",
}

MAX_RESULTS = 5000
MAX_TOP_ITEMS = 30


class DataStore:
    def __init__(self, data_dir):
        self.path = Path(data_dir).expanduser().resolve()
        if not self.path.is_dir():
            raise FileNotFoundError(f"Cannot find data folder: {self.path}")

        missing = [name for name in REQUIRED if not (self.path / name).is_file()]
        if missing:
            raise FileNotFoundError("Missing dataset CSVs: " + ", ".join(missing))

        self.con = duckdb.connect(":memory:")
        self.con.execute("SET memory_limit='2GB'")
        # The default temp folder is inside the working directory, which the
        # server's sandbox makes read-only. /tmp is private and writable.
        self.con.execute("SET temp_directory=?", [str(Path(tempfile.gettempdir()) / "duckdb")])
        self.con.execute("SET threads=4")
        self.tables = []
        self.skipped = []

        try:
            for table, filename in DATASETS.items():
                file_path = self.path / filename
                if not file_path.is_file():
                    continue

                # Force the CSV dialect instead of relying on auto-detection.
                # Keeping strict parsing avoids silently dropping malformed rows.
                # The filename is a trusted, locally configured path.
                try:
                    self.con.execute(
                        f'CREATE TABLE "{table}" AS SELECT * FROM read_csv('
                        "?, delim=',', quote='\"', escape='\"', "
                        "header=true, all_varchar=true, "
                        "strict_mode=true, ignore_errors=false)",
                        [str(file_path)],
                    )
                    self.tables.append(table)
                except duckdb.Error:
                    if filename in REQUIRED:
                        raise
                    # A malformed optional dataset is skipped so the rest still works.
                    self.skipped.append(filename)
        except Exception:
            self.con.close()
            raise

    def query(self, sql, args=()):
        """Run SQL authored by this module, using a cursor per request/thread."""
        cursor = self.con.cursor()
        try:
            return cursor.execute(sql, list(args)).df()
        finally:
            cursor.close()

    @staticmethod
    def _top_limit(limit):
        return max(1, min(int(limit), MAX_TOP_ITEMS))

    def overview(self):
        counts = self.query("""
            SELECT
                (SELECT COUNT(*) FROM vulnerabilities) AS vulnerabilities,
                (SELECT COUNT(*) FROM scoreboard) AS scoreboard,
                (SELECT COUNT(*) FROM known_exploited) AS historical_kev,
                (SELECT COUNT(*) FROM scoreboard
                 WHERE TRY_CAST(epss AS DOUBLE) IS NOT NULL) AS epss_coverage
        """).iloc[0]
        return {key: int(counts[key]) for key in
                ("vulnerabilities", "scoreboard", "historical_kev", "epss_coverage")}

    def top_vendors(self, year=None, limit=12, measure="count"):
        limit = self._top_limit(limit)
        if measure not in ("count", "kev_rate"):
            raise ValueError("measure must be 'count' or 'kev_rate'")

        where = "WHERE upper(trim(p.vulnerable)) = 'Y' AND NULLIF(trim(p.vendor), '') IS NOT NULL"
        args = []
        if year is not None:
            where += " AND EXTRACT(YEAR FROM TRY_CAST(v.published AS DATE)) = ?"
            args.append(int(year))

        if measure == "kev_rate":
            sql = f"""
                WITH per_vendor AS (
                    SELECT DISTINCT lower(trim(p.vendor)) AS vendor, p.cve_id
                    FROM affected_products p
                    JOIN vulnerabilities v ON p.cve_id = v.cve_id
                    {where}
                ), kev_ids AS (
                    SELECT DISTINCT cve_id FROM known_exploited
                ), stats AS (
                    SELECT a.vendor, COUNT(*) AS total_cves,
                           COUNT(k.cve_id) AS kev_cves
                    FROM per_vendor a
                    LEFT JOIN kev_ids k ON a.cve_id = k.cve_id
                    GROUP BY a.vendor
                )
                SELECT vendor, total_cves, kev_cves,
                    ROUND(100.0 * kev_cves / NULLIF(total_cves, 0), 3) AS kev_rate_pct
                FROM stats WHERE total_cves >= 100
                ORDER BY kev_rate_pct DESC, total_cves DESC, vendor
                LIMIT {limit}
            """
        else:
            sql = f"""
                SELECT lower(trim(p.vendor)) AS vendor,
                       COUNT(DISTINCT p.cve_id) AS vulnerabilities
                FROM affected_products p
                JOIN vulnerabilities v ON p.cve_id = v.cve_id
                {where}
                GROUP BY 1
                ORDER BY vulnerabilities DESC, vendor
                LIMIT {limit}
            """
        return self.query(sql, args)

    def top_cwes(self, year=None, limit=15):
        args = []
        where = "WHERE NULLIF(trim(v.cwe_ids), '') IS NOT NULL"
        if year is not None:
            where += " AND EXTRACT(YEAR FROM TRY_CAST(v.published AS DATE)) = ?"
            args.append(int(year))

        if "weakness_types" in self.tables:
            weakness_expr = "COALESCE(MAX(w.name), '(no catalog entry)')"
            weakness_join = "LEFT JOIN weakness_types w ON vals.cwe_id = w.cwe_id"
        else:
            weakness_expr = "'(not available)'"
            weakness_join = ""

        sql = f"""
            WITH vals AS (
                SELECT v.cve_id, trim(unnest(string_split(v.cwe_ids, ';'))) AS cwe_id
                FROM vulnerabilities v {where}
            ), kev_ids AS (
                SELECT DISTINCT cve_id FROM known_exploited
            )
            SELECT vals.cwe_id, {weakness_expr} AS weakness,
                   COUNT(DISTINCT vals.cve_id) AS vulnerabilities,
                   COUNT(DISTINCT k.cve_id) AS historical_kev
            FROM vals
            {weakness_join}
            LEFT JOIN kev_ids k ON vals.cve_id = k.cve_id
            WHERE NULLIF(vals.cwe_id, '') IS NOT NULL
            GROUP BY vals.cwe_id
            ORDER BY vulnerabilities DESC, vals.cwe_id
            LIMIT {self._top_limit(limit)}
        """
        return self.query(sql, args)

    def published_years(self):
        return self.query("""
            SELECT EXTRACT(YEAR FROM TRY_CAST(published AS DATE))::INT AS year,
                   COUNT(*) AS vulnerabilities
            FROM vulnerabilities
            WHERE TRY_CAST(published AS DATE) IS NOT NULL
            GROUP BY 1 ORDER BY 1
        """)

    def ranking(self, n=500, min_epss=0, exploit_only=False):
        limit = max(1, min(int(n), MAX_RESULTS))
        min_epss = float(min_epss)
        if not 0 <= min_epss <= 1:
            raise ValueError("min_epss must be between 0 and 1")
        filter_sql = "WHERE epss >= ?"
        if exploit_only:
            filter_sql += " AND any_exploit = 1"

        sql = f"""
            WITH scored AS (
                SELECT cve_id, published, snapshot_month,
                       COALESCE(TRY_CAST(epss AS DOUBLE), 0) AS epss,
                       COALESCE(TRY_CAST(exploitdb AS INTEGER), 0) AS exploitdb,
                       COALESCE(TRY_CAST(metasploit AS INTEGER), 0) AS metasploit,
                       COALESCE(TRY_CAST(nuclei AS INTEGER), 0) AS nuclei,
                       COALESCE(TRY_CAST(poc_github AS INTEGER), 0) AS poc_github
                FROM scoreboard
            ), flagged AS (
                SELECT *,
                    ((exploitdb + metasploit + nuclei + poc_github) > 0)::INT AS any_exploit
                FROM scored
            ), ordered AS (
                SELECT *, ROW_NUMBER() OVER (
                    ORDER BY any_exploit DESC, epss DESC, cve_id ASC
                ) AS priority_rank
                FROM flagged
            )
            SELECT * FROM ordered
            {filter_sql}
            ORDER BY priority_rank LIMIT {limit}
        """
        return self.query(sql, [min_epss])

    def cve(self, cve_id):
        return self.query("""
            SELECT v.cve_id, v.published, v.description, v.cvss3_score,
                   v.cvss3_severity, v.cwe_ids, v.attack_vector,
                   v.privileges_required, v.user_interaction,
                   s.snapshot_month, s.epss, s.exploitdb, s.metasploit,
                   s.nuclei, s.poc_github,
                   k.date_added AS historical_kev_date
            FROM vulnerabilities v
            LEFT JOIN scoreboard s USING (cve_id)
            LEFT JOIN known_exploited k USING (cve_id)
            WHERE upper(v.cve_id) = upper(?)
            LIMIT 1
        """, [cve_id])

    def cve_products(self, cve_id):
        return self.query("""
            SELECT DISTINCT vendor, product, type
            FROM affected_products
            WHERE upper(cve_id) = upper(?) AND upper(trim(vulnerable)) = 'Y'
            ORDER BY vendor, product LIMIT 20
        """, [cve_id])

    def highest_epss(self, n=10, exploit_only=False):
        # Retains the existing API: this is priority-ranked, not purely EPSS-ranked.
        return self.ranking(n=n, exploit_only=exploit_only)

    def signals_history(self, cve_id):
        available = [t for t in ("signals_2024", "signals_2025") if t in self.tables]
        if not available:
            return pd.DataFrame()

        selections = [f"""
            SELECT month, TRY_CAST(epss AS DOUBLE) AS epss,
                   in_kev, exploitdb, metasploit, nuclei, poc_github
            FROM {table} WHERE upper(cve_id) = upper(?)
        """ for table in available]
        return self.query(
            "SELECT * FROM (" + " UNION ALL ".join(selections) + ") ORDER BY month",
            [cve_id] * len(available),
        )

    def kev_vendors(self, limit=12):
        return self.query(f"""
            SELECT vendor, COUNT(*) AS known_exploited
            FROM known_exploited
            WHERE NULLIF(trim(vendor), '') IS NOT NULL
            GROUP BY vendor
            ORDER BY known_exploited DESC, vendor
            LIMIT {self._top_limit(limit)}
        """)

    def kev_ransomware(self):
        return self.query("""
            SELECT known_ransomware_use AS ransomware_status,
                   COUNT(*) AS vulnerabilities
            FROM known_exploited
            GROUP BY 1 ORDER BY vulnerabilities DESC
        """)

    def dataset_catalog(self):
        result = []
        for name in self.tables:
            desc = self.query(f'DESCRIBE "{name}"')
            result.append({"table": name, "columns": ", ".join(desc["column_name"].tolist())})
        return pd.DataFrame(result)

    def close(self):
        self.con.close()
