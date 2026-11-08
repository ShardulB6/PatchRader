"""Read-only, narrowly-scoped analytics against challenge CSVs."""
from pathlib import Path
import os
import duckdb
import pandas as pd

REQUIRED = ['vulnerabilities.csv','affected_products.csv','known_exploited.csv','scoreboard_2026.csv']
OPTIONAL = ['references.csv','weakness_types.csv','exploit_signals_2024.csv','exploit_signals_2025.csv']

class DataStore:
    def __init__(self, data_dir):
        self.path = Path(data_dir).expanduser().resolve()
        if not self.path.is_dir():
            raise FileNotFoundError(f'Cannot find data folder: {self.path}')
        missing = [f for f in REQUIRED if not (self.path/f).exists()]
        if missing:
            raise FileNotFoundError('Missing dataset CSVs: '+', '.join(missing))
        self.con = duckdb.connect(':memory:')
        self.con.execute("SET memory_limit='2GB'")
        self.con.execute('SET threads=4')
        names = {
            'vulnerabilities':'vulnerabilities.csv',
            'affected_products':'affected_products.csv',
            'known_exploited':'known_exploited.csv',
            'scoreboard':'scoreboard_2026.csv',
            'weakness_types':'weakness_types.csv',
            'references':'references.csv',
            'signals_2024':'exploit_signals_2024.csv',
            'signals_2025':'exploit_signals_2025.csv',
        }
        self.tables = []
        for table, file in names.items():
            f = self.path/file
            if f.exists():
                # All VARCHAR avoids auto-detection of mixed version columns.
                p = str(f).replace("'", "''")
                self.con.execute(
                    f'CREATE VIEW "{table}" AS SELECT * '
                    f"FROM read_csv('{p}', all_varchar=true, header=true, ignore_errors=false)"
                )
                self.tables.append(table)

    def query(self, sql, args=()):
        # SQL must be authored in this module, not passed from a language model.
        return self.con.execute(sql, list(args)).df()

    def overview(self):
        a = self.query('SELECT COUNT(*) AS n FROM vulnerabilities').iloc[0]['n']
        b = self.query('SELECT COUNT(*) AS n FROM scoreboard').iloc[0]['n']
        c = self.query('SELECT COUNT(*) AS n FROM known_exploited').iloc[0]['n']
        d = self.query("SELECT COUNT(*) AS n FROM scoreboard WHERE TRY_CAST(epss AS DOUBLE) IS NOT NULL").iloc[0]['n']
        return dict(vulnerabilities=int(a), scoreboard=int(b), historical_kev=int(c), epss_coverage=int(d))

    def top_vendors(self, year=None, limit=12, measure='count'):
        limit = max(1, min(int(limit), 30))
        where = "WHERE p.vulnerable = 'Y' AND p.vendor IS NOT NULL AND p.vendor <> ''"
        args = []
        if year is not None:
            where += " AND EXTRACT(YEAR FROM TRY_CAST(v.published AS DATE)) = ?"
            args.append(int(year))
        # Dedupes vendor/CVE, even if many affected versions listed.
        if measure == 'kev_rate':
            sql = f"""WITH per_vendor AS (
                SELECT DISTINCT lower(p.vendor) AS vendor, p.cve_id
                FROM affected_products p JOIN vulnerabilities v ON p.cve_id=v.cve_id {where}
            ), stats AS (
                SELECT vendor, COUNT(*) AS total_cves,
                COUNT(k.cve_id) AS kev_cves
                FROM per_vendor a LEFT JOIN (SELECT DISTINCT cve_id FROM known_exploited) k
                ON a.cve_id=k.cve_id GROUP BY vendor
            ) SELECT vendor,total_cves,kev_cves,
                ROUND(100.0*kev_cves/NULLIF(total_cves,0),3) AS kev_rate_pct
              FROM stats WHERE total_cves >= 100
              ORDER BY kev_rate_pct DESC, total_cves DESC LIMIT {limit}"""
        else:
            sql = f"""SELECT lower(p.vendor) AS vendor, COUNT(DISTINCT p.cve_id) AS vulnerabilities
              FROM affected_products p JOIN vulnerabilities v ON p.cve_id=v.cve_id
              {where} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}"""
        return self.query(sql,args)

    def top_cwes(self, year=None, limit=15):
        args=[]
        where='WHERE v.cwe_ids IS NOT NULL'
        if year is not None:
            where+=' AND EXTRACT(YEAR FROM TRY_CAST(v.published AS DATE)) = ?'
            args.append(int(year))
        sql=f"""WITH vals AS (
            SELECT v.cve_id, trim(unnest(string_split(v.cwe_ids,';'))) AS cwe_id
            FROM vulnerabilities v {where}
        ) SELECT vals.cwe_id, COALESCE(MAX(w.name), '(no catalog entry)') AS weakness,
          COUNT(DISTINCT vals.cve_id) AS vulnerabilities,
          COUNT(DISTINCT k.cve_id) AS historical_kev
          FROM vals LEFT JOIN weakness_types w ON vals.cwe_id=w.cwe_id
          LEFT JOIN known_exploited k ON vals.cve_id=k.cve_id
          GROUP BY 1 ORDER BY vulnerabilities DESC LIMIT {max(1,min(int(limit),30))}"""
        if 'weakness_types' not in self.tables:
            sql=sql.replace("COALESCE(MAX(w.name), '(no catalog entry)')", "'(not available)'")
            sql=sql.replace(' LEFT JOIN weakness_types w ON vals.cwe_id=w.cwe_id','')
        return self.query(sql,args)

    def published_years(self):
        return self.query("""SELECT EXTRACT(YEAR FROM TRY_CAST(published AS DATE))::INT AS year,
                 COUNT(*) AS vulnerabilities FROM vulnerabilities WHERE TRY_CAST(published AS DATE) IS NOT NULL
                 GROUP BY 1 ORDER BY 1""")

    def ranking(self, n=500, min_epss=0, exploit_only=False):
        where = "WHERE COALESCE(TRY_CAST(epss AS DOUBLE),0) >= ?"
        if exploit_only:
            where += " AND (COALESCE(TRY_CAST(exploitdb AS INT),0)+COALESCE(TRY_CAST(metasploit AS INT),0)+COALESCE(TRY_CAST(nuclei AS INT),0)+COALESCE(TRY_CAST(poc_github AS INT),0))>0"
        sql = f"""WITH scored AS (
              SELECT cve_id, published, snapshot_month,
              COALESCE(TRY_CAST(epss AS DOUBLE),0) AS epss,
              COALESCE(TRY_CAST(exploitdb AS INT),0) AS exploitdb,
              COALESCE(TRY_CAST(metasploit AS INT),0) AS metasploit,
              COALESCE(TRY_CAST(nuclei AS INT),0) AS nuclei,
              COALESCE(TRY_CAST(poc_github AS INT),0) AS poc_github
              FROM scoreboard
            ), ordered AS (
              SELECT *, (exploitdb+metasploit+nuclei+poc_github>0)::INT AS any_exploit,
              ROW_NUMBER() OVER (ORDER BY (exploitdb+metasploit+nuclei+poc_github>0) DESC, epss DESC, cve_id ASC) AS priority_rank
              FROM scored
            ) SELECT * FROM ordered {where}
            ORDER BY priority_rank LIMIT {max(1,min(int(n),72670))}"""
        return self.query(sql,[float(min_epss)])

    def cve(self, cve_id):
        return self.query("""SELECT v.cve_id,v.published,v.description,v.cvss3_score,v.cvss3_severity,
             v.cwe_ids,v.attack_vector,v.privileges_required,v.user_interaction,
             s.snapshot_month, s.epss, s.exploitdb, s.metasploit,s.nuclei,s.poc_github,
             k.date_added AS historical_kev_date
             FROM vulnerabilities v
             LEFT JOIN scoreboard s USING(cve_id)
             LEFT JOIN known_exploited k USING(cve_id)
             WHERE upper(v.cve_id)=upper(?) LIMIT 1""",[cve_id])

    def cve_products(self,cve_id):
        return self.query("""SELECT DISTINCT vendor,product,type
             FROM affected_products WHERE cve_id=? AND vulnerable='Y' LIMIT 20""",[cve_id])

    def highest_epss(self, n=10, exploit_only=False):
        return self.ranking(n=n, exploit_only=exploit_only)

    def signals_history(self,cve_id):
        if not all(x in self.tables for x in ['signals_2024','signals_2025']):
            return pd.DataFrame()
        return self.query("""SELECT * FROM (
          SELECT month,TRY_CAST(epss AS DOUBLE) AS epss,in_kev,exploitdb,metasploit,nuclei,poc_github
          FROM signals_2024 WHERE cve_id=?
          UNION ALL
          SELECT month,TRY_CAST(epss AS DOUBLE) AS epss,in_kev,exploitdb,metasploit,nuclei,poc_github
          FROM signals_2025 WHERE cve_id=?
          ) ORDER BY month""",[cve_id,cve_id])

    def kev_vendors(self, limit=12):
        return self.query(f"""SELECT vendor, COUNT(*) AS known_exploited
           FROM known_exploited WHERE vendor IS NOT NULL
           GROUP BY vendor ORDER BY known_exploited DESC LIMIT {max(1,min(int(limit),30))}""")

    def kev_ransomware(self):
        return self.query("""SELECT known_ransomware_use AS ransomware_status, COUNT(*) AS vulnerabilities
          FROM known_exploited GROUP BY 1 ORDER BY vulnerabilities DESC""")

    def dataset_catalog(self):
        result=[]
        for name in self.tables:
            desc=self.query(f'DESCRIBE "{name}"')
            result.append({'table':name,'columns':', '.join(desc['column_name'].tolist())})
        return pd.DataFrame(result)
