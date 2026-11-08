"""
Engineered Track A features (Phase 4b). Builds on features.py: call F.build_features first,
then add_engineered_features. Everything is point-in-time (known at the end of `snap`).

    import features as F, features_extra as FX
    hist = F.History(con); hx = FX.ExtraHistory(con)
    df = FX.add_engineered_features(F.build_features(df, hist), hx)
"""
import re
import numpy as np
import pandas as pd

# KEV product names that are ordinary words or too broad to identify a product in free text.
GENERIC_PRODUCTS = {"kernel", "framework", "windows", "office", "webmail", "chromium", "pixel", "ios", "macos",
                    "android", "firefox", "java se", "server", "router", "routers", "firmware", "multiple",
                    "core", "project", "desktop", "web server", "tools", "edge", "frontend", "viewer", "reader",
                    "firewall", "client", "gateway", "portal", "console", "agent", "manager", "platform", "suite",
                    "studio", "cloud", "connect", "mail", "explorer", "player", "plugin", "apache", "sense",
                    "network", "devices", "access", "camera", "cameras", "storage", "system", "systems", "software",
                    "management", "center", "service", "services", "browser", "media", "remote", "security"}


CWE_NEUTRAL_RATE = 0.004  # about the overall KEV rate across all CVEs (1,484 / 401,082)


def _norm_product(p):
    p = re.sub(r"\(.*?\)", "", str(p).lower()).strip()
    return re.sub(r"\s+", " ", p)


class ExtraHistory:
    """Dated KEV history by product name and by weakness type (CWE), loaded once."""

    def __init__(self, con):
        kev = con.sql("""
            SELECT k.cve_id, MIN(CAST(k.date_added AS DATE)) AS date_added, ANY_VALUE(k.product) AS product,
                   ANY_VALUE(v.cwe_ids) AS cwe_ids
            FROM known_exploited k LEFT JOIN vulnerabilities v USING (cve_id) GROUP BY k.cve_id""").df()
        kev["date_added"] = pd.to_datetime(kev["date_added"])
        kev["pkey"] = kev["product"].map(_norm_product)
        keep = kev[(kev.pkey.str.len() >= 4) & ~kev.pkey.str.startswith("multiple") & ~kev.pkey.isin(GENERIC_PRODUCTS)]
        self.kev_by_product = {k: np.sort(g["date_added"].values) for k, g in keep.groupby("pkey")}
        keys = sorted(self.kev_by_product, key=len, reverse=True)
        self.product_re = re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(k) for k in keys) + r")(?![a-z0-9])")

        def explode(df, date_col):
            e = df[["cwe_ids", date_col]].dropna().copy()
            e["cwe"] = e["cwe_ids"].str.split(";")
            e = e.explode("cwe")
            return e[e.cwe.str.startswith("CWE-")]
        ke = explode(kev, "date_added")
        self.kev_by_cwe = {c: np.sort(g["date_added"].values) for c, g in ke.groupby("cwe")}
        allv = con.sql("SELECT cwe_ids, CAST(published AS DATE) AS published FROM vulnerabilities").df()
        allv["published"] = pd.to_datetime(allv["published"])
        ae = explode(allv, "published")
        self.pubs_by_cwe = {c: np.sort(g["published"].values) for c, g in ae.groupby("cwe")}
        kv = con.sql("""SELECT v.assigner, MIN(CAST(k.date_added AS DATE)) AS date_added
                        FROM known_exploited k JOIN vulnerabilities v USING (cve_id) GROUP BY k.cve_id, v.assigner""").df()
        self.kev_by_assigner = {a: np.sort(pd.to_datetime(g["date_added"]).values) for a, g in kv.groupby("assigner")}
        pv = con.sql("SELECT assigner, CAST(published AS DATE) AS published FROM vulnerabilities").df()
        self.pubs_by_assigner = {a: np.sort(pd.to_datetime(g["published"]).values) for a, g in pv.dropna().groupby("assigner")}


def _count_between(arr, lo, hi):
    if arr is None:
        return 0
    return np.searchsorted(arr, hi, side="right") - np.searchsorted(arr, lo, side="right")


def add_engineered_features(df, hx):
    df = df.copy()
    snap_end = pd.PeriodIndex(df["snap"], freq="M").end_time.normalize()
    ends = snap_end.to_numpy()
    year_before = (snap_end - pd.Timedelta(days=365)).to_numpy()
    never = np.datetime64("1900-01-01")

    # 1. Interactions: combinations of features that already replicate
    df["net_preauth"] = df["av_network"] * df["pr_none"] * df["ui_none"]          # reachable over the network, no login, no click
    df["assigner_pct"] = df["log_assigner_kev_rate"].rank(pct=True)                 # 0-1 within the set, so scales match across years
    df["exploit_x_assigner"] = df["any_exploit"] * df["assigner_pct"]
    df["unauth_x_assigner"] = df["kw_unauth"] * df["assigner_pct"]
    df["preauth_x_assigner"] = df["net_preauth"] * df["assigner_pct"]
    df["epss_x_assigner"] = df["epss_pct"] * df["assigner_pct"]
    df["exploit_sources"] = df[["exploitdb", "metasploit", "nuclei", "poc_github"]].sum(axis=1)

    # 2. Batch ("sibling") features: CVEs from the same assigner published the same day,
    #    usually one advisory. Uses only snapshot signals of the batch's other members.
    g = df.groupby(["assigner", "published"])
    df["batch_size"] = g["cve_id"].transform("size")
    df["batch_exploit_others"] = ((g["any_exploit"].transform("sum") - df["any_exploit"]) > 0).astype(int)
    df["batch_max_epss_others"] = g["epss_pct"].transform(
        lambda s: pd.Series([s.drop(i).max() if len(s) > 1 else 0.0 for i in s.index], index=s.index))
    df["log_batch_size"] = np.log1p(df["batch_size"])

    # 3. Product-level KEV history: KEV product names found in the description, counted up to the snapshot
    text = df["description"].fillna("").str.lower().to_numpy()
    prod_prior, prod_name = np.zeros(len(df), dtype=int), []
    for i, (t, e) in enumerate(zip(text, ends)):
        best, name = 0, ""
        for k in set(hx.product_re.findall(t)):
            c = np.searchsorted(hx.kev_by_product[k], e, side="right")
            if c > best:
                best, name = c, k
        prod_prior[i] = best; prod_name.append(name)
    df["product_kev_prior"] = prod_prior
    df["product_has_kev"] = (prod_prior > 0).astype(int)
    df["product_match"] = prod_name

    # 4. Weakness-type (CWE) KEV rate: the most-exploited CWE among the row's CWEs, point-in-time
    rates = np.zeros(len(df))
    for i, (s, e) in enumerate(zip(df["cwe_ids"].fillna("").to_numpy(), ends)):
        best = 0.0
        for c in s.split(";"):
            if not c.startswith("CWE-"):
                continue
            k = _count_between(hx.kev_by_cwe.get(c), never, e)
            n = _count_between(hx.pubs_by_cwe.get(c), never, e)
            best = max(best, (k + 0.1) / (n + 100))
        rates[i] = best if best > 0 else np.nan
    # A missing CWE usually means NIST hasn't reviewed the CVE yet, and unreviewed CVEs are rarely
    # positives, so "missing -> low rate" would leak the review. Fill with a neutral value instead.
    df["cwe_missing"] = np.isnan(rates).astype(int)
    df["log_cwe_kev_rate"] = np.log(np.where(np.isnan(rates), CWE_NEUTRAL_RATE, rates))

    # 5. Assigner recency: KEV entries and CVEs in the 12 months before the snapshot
    a = df["assigner"].to_numpy()
    k12 = np.array([_count_between(hx.kev_by_assigner.get(x), lo, hi) for x, lo, hi in zip(a, year_before, ends)])
    n12 = np.array([_count_between(hx.pubs_by_assigner.get(x), lo, hi) for x, lo, hi in zip(a, year_before, ends)])
    df["assigner_kev_12m"] = k12
    df["log_assigner_rate_12m"] = np.log((k12 + 0.1) / (n12 + 50))

    # 6. Exposure: days between publication and the snapshot (more days = more time for signals to appear)
    df["days_observed"] = (snap_end - pd.to_datetime(df["published"])).dt.days.to_numpy()
    return df
