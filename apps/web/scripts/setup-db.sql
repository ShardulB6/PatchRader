-- Safe to run again. Mirrored for queries by src/db/schema.ts.
CREATE TABLE IF NOT EXISTS exploit_signals (
  month date NOT NULL, -- last day of the month the values describe
  cve_id text NOT NULL,
  epss double precision,
  in_kev boolean NOT NULL,
  exploitdb boolean NOT NULL,
  metasploit boolean NOT NULL,
  nuclei boolean NOT NULL,
  poc_github boolean NOT NULL,
  source text NOT NULL CHECK (source IN ('signals', 'scoreboard')),
  PRIMARY KEY (month, cve_id)
);

SELECT create_hypertable('exploit_signals', by_range('month', INTERVAL '1 month'), if_not_exists => TRUE);

-- Each monthly chunk holds one row per CVE, so grouping by cve_id would compress
-- nothing. Sorting by it keeps similar rows together and speeds up lookups.
ALTER TABLE exploit_signals SET (
  timescaledb.enable_columnstore = TRUE,
  timescaledb.segmentby = '',
  timescaledb.orderby = 'cve_id'
);
