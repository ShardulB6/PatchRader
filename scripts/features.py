"""
Track A feature builder (Phase 4). Works on the backtest sets from phase3_backtest
(train_2024, val_2025) and on scoreboard_2026, so every set gets identical columns.

Every feature uses only what was known at the end of the row's snapshot month:
  - `snap` (YYYY-MM) is the snapshot month: the publish month for backtest rows,
    `snapshot_month` for scoreboard rows (June 2026 rows use July).
  - KEV history counts only KEV entries added on or before the end of `snap`.
  - No banned columns (nvd_status, n_affected_cpes, n_references, cvss3_source,
    last_modified, affected_products, references).

Usage:
    import features as F
    hist = F.History(con)                       # load KEV + assigner history once
    train_f = F.build_features(train, hist)
    val_f   = F.build_features(val, hist)
"""
import numpy as np
import pandas as pd

FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]

# Keyword flags on the description (lower-cased regex).
KEYWORDS = {
    "kw_unauth": r"unauthenticated|without authentication|unauthorized remote|authentication bypass|bypass authentication",
    "kw_rce": r"remote code execution|execute arbitrary (?:code|commands)|arbitrary code execution|code execution",
    "kw_path_traversal": r"path traversal|directory traversal",
    "kw_deserialization": r"deserializ",
    "kw_cmd_injection": r"command injection|os command",
    "kw_edge_device": r"\bvpn\b|ssl-vpn|sslvpn|firewall|gateway|router|appliance|management interface",
    "kw_privesc_local": r"local (?:user|attacker)s?|elevation of privilege|privilege escalation",
    "kw_sqli": r"sql injection",
    "kw_xss": r"cross-site scripting|\bxss\b",
    "kw_dos": r"denial of service|\bdos\b|crash",
    "kw_wordpress": r"wordpress",
    "kw_linux_kernel": r"^in the linux kernel",
}

# Weakness-type groups (cwe_ids is ';'-separated).
CWE_GROUPS = {
    "cwe_auth": ["CWE-287", "CWE-288", "CWE-306", "CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-290", "CWE-798", "CWE-639"],
    "cwe_path": ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
    "cwe_deser": ["CWE-502"],
    "cwe_injection": ["CWE-77", "CWE-78", "CWE-94", "CWE-89", "CWE-917", "CWE-1336", "CWE-74", "CWE-95"],
    "cwe_memory": ["CWE-787", "CWE-125", "CWE-416", "CWE-119", "CWE-122", "CWE-121", "CWE-190", "CWE-843", "CWE-120"],
    "cwe_xss": ["CWE-79"],
}

CVSS_FILL = 7.5  # neutral fill for a blank CVSS score: blank scores leak NIST's review (see Phase 4, section 6)


class History:
    """Dated history needed for point-in-time features, loaded once."""

    def __init__(self, con):
        kev = con.sql("""
            SELECT k.cve_id, MIN(CAST(k.date_added AS DATE)) AS date_added, ANY_VALUE(v.assigner) AS assigner
            FROM known_exploited k LEFT JOIN vulnerabilities v USING (cve_id)
            GROUP BY k.cve_id""").df()
        pubs = con.sql("SELECT assigner, CAST(published AS DATE) AS published FROM vulnerabilities").df()
        self.kev_by_assigner = {a: np.sort(pd.to_datetime(g["date_added"]).values)
                                for a, g in kev.dropna(subset=["assigner"]).groupby("assigner")}
        self.pubs_by_assigner = {a: np.sort(pd.to_datetime(g["published"]).values)
                                 for a, g in pubs.dropna(subset=["assigner"]).groupby("assigner")}
        self.kev_last_date = pd.to_datetime(kev["date_added"]).max()

    @staticmethod
    def _count_upto(table, keys, ends):
        empty = np.array([], dtype="datetime64[ns]")
        return np.array([np.searchsorted(table.get(k, empty), e, side="right") for k, e in zip(keys, ends)])

    def assigner_counts(self, assigner, snap_end):
        kev = self._count_upto(self.kev_by_assigner, assigner, snap_end)
        vol = self._count_upto(self.pubs_by_assigner, assigner, snap_end)
        return kev, vol


def build_features(df, hist):
    """Return a copy of df with all Track A candidate features added."""
    df = df.copy()
    snap_end = (pd.PeriodIndex(df["snap"], freq="M").end_time.normalize()).to_numpy()

    # 1. Exploit signals at the snapshot
    for f in FLAGS:
        df[f] = df[f].fillna(0).astype(int)
    df["any_exploit"] = (df[FLAGS].sum(axis=1) > 0).astype(int)
    df["signal_missing"] = df["epss"].isna().astype(int)
    # EPSS percentile within its own snapshot month: compares like with like across EPSS model versions
    df["epss_pct"] = df.groupby("snap")["epss"].rank(pct=True).fillna(0)

    # 2. Assigner history (point-in-time)
    kev, vol = hist.assigner_counts(df["assigner"].to_numpy(), snap_end)
    df["assigner_kev_prior"] = kev
    df["assigner_vol_prior"] = vol
    df["assigner_has_kev"] = (kev > 0).astype(int)
    # Smoothed KEV rate: an assigner with no history starts near the overall rate, not at 0 or 1
    df["assigner_kev_rate"] = (kev + 0.1) / (vol + 100)
    df["log_assigner_kev_rate"] = np.log(df["assigner_kev_rate"])

    # 3. CVSS parts (Careful columns: values only, never "is blank")
    df["cvss_filled"] = df["cvss3_score"].fillna(CVSS_FILL)
    df["cvss_critical"] = (df["cvss3_score"] >= 9.0).astype(int)
    df["av_network"] = (df["attack_vector"] == "NETWORK").astype(int)
    df["pr_none"] = (df["privileges_required"] == "NONE").astype(int)
    df["ui_none"] = (df["user_interaction"] == "NONE").astype(int)

    # 4. Description keywords and weakness types
    text = df["description"].fillna("").str.lower()
    for name, pattern in KEYWORDS.items():
        df[name] = text.str.contains(pattern, regex=True).astype(int)
    cwe = df["cwe_ids"].fillna("").str.split(";")
    for name, ids in CWE_GROUPS.items():
        idset = set(ids)
        df[name] = cwe.map(lambda xs: int(bool(idset.intersection(xs))))
    return df


def scoreboard_frame(con):
    """scoreboard_2026 joined to the safe vulnerabilities columns, shaped like the backtest sets."""
    return con.sql("""
        SELECT s.cve_id, CAST(s.published AS DATE) AS published, s.snapshot_month AS snap,
               v.assigner, v.description, CAST(v.cvss3_score AS DOUBLE) AS cvss3_score,
               v.attack_vector, v.attack_complexity, v.privileges_required, v.user_interaction,
               v.scope, v.cwe_ids, CAST(s.epss AS DOUBLE) AS epss,
               s.exploitdb, s.metasploit, s.nuclei, s.poc_github
        FROM scoreboard_2026 s LEFT JOIN vulnerabilities v USING (cve_id)""").df()
