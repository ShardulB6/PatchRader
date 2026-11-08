"""Qualitative impact profiles for a list of CVEs, derived only from dataset fields.

Footprint is measured in affected vendors/products (a proxy). Nothing here
estimates customer counts or financial damage.
"""
import re
from collections import Counter
from pathlib import Path

import pandas as pd

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

# CWE name keyword -> (harm category, plain-language effect)
HARM_DICT = [
    ("sql injection", "data_breach", "stored records can be read or altered through the application"),
    ("command injection", "system_takeover", "attackers can run their own commands on the system"),
    ("code injection", "system_takeover", "attackers can run their own code on the system"),
    ("buffer", "system_takeover", "memory corruption that often leads to crashes or full control"),
    ("out-of-bounds write", "system_takeover", "memory corruption that often leads to crashes or full control"),
    ("out-of-bounds read", "data_exposure", "memory contents can leak to an attacker"),
    ("use after free", "system_takeover", "memory corruption that often leads to crashes or full control"),
    ("deserialization", "system_takeover", "crafted data can trigger code execution"),
    ("authentication", "unauthorized_access", "services can be accessed without legitimate credentials"),
    ("authorization", "unauthorized_access", "users can reach data or functions they should not"),
    ("access control", "unauthorized_access", "users can reach data or functions they should not"),
    ("privilege management", "privilege_escalation", "a low-privileged user can gain administrator-level control"),
    ("upload of file", "system_takeover", "a malicious file can be uploaded and may then be run"),
    ("server-side request forgery", "internal_network_access", "the server can be abused to reach internal systems"),
    ("file name or path", "data_breach", "files outside the intended folder can be read or overwritten"),
    ("credential", "credential_theft", "passwords or keys may be exposed, enabling follow-on attacks"),
    ("cross-site scripting", "user_compromise", "visitors can be attacked through a trusted site"),
    ("cookie", "session_hijack", "user sessions may be stolen or tampered with"),
    ("path traversal", "data_breach", "files outside the intended folder can be read or overwritten"),
    ("resource consumption", "service_disruption", "services can be exhausted and made unavailable"),
    ("allocation of resources", "service_disruption", "services can be exhausted and made unavailable"),
    ("infinite loop", "service_disruption", "services can be hung or made unavailable"),
    ("cryptograph", "data_exposure", "protected data may be readable or forgeable"),
    ("information exposure", "data_exposure", "sensitive information leaks to unintended parties"),
    ("exposure of sensitive", "data_exposure", "sensitive information leaks to unintended parties"),
]

# Description regex -> (harm category, effect). Many new CVEs have no CWE yet.
DESC_RULES = [
    (r"remote code execution|arbitrary code|arbitrary commands?|command injection", "system_takeover",
     "attackers can run their own code or commands on the system"),
    (r"sql injection", "data_breach", "stored records can be read or altered through the application"),
    (r"denial of service|infinite loop|resource exhaustion|application crash", "service_disruption",
     "services can be crashed or made unavailable"),
    (r"privilege escalation|escalate privileges|elevation of privilege|gain (?:root|admin)", "privilege_escalation",
     "a low-privileged user can gain administrator-level control"),
    (r"authentication bypass|bypass authentication|without authentication|missing authentication",
     "unauthorized_access", "services can be accessed without legitimate credentials"),
    (r"information disclosure|disclose sensitive|read arbitrary files|sensitive information", "data_exposure",
     "sensitive information leaks to unintended parties"),
    (r"cross-site scripting|\bxss\b|cross-site request forgery|\bcsrf\b", "user_compromise",
     "users can be attacked through a trusted site"),
    (r"path traversal|directory traversal", "data_breach", "files outside the intended folder can be read or overwritten"),
    (r"server-side request forgery|\bssrf\b", "internal_network_access",
     "the server can be abused to reach internal systems"),
    (r"hard-?coded (?:credential|password|key)", "credential_theft",
     "embedded credentials can be reused by anyone who finds them"),
]

# Heuristic: where these vendors' products typically sit. Extend freely.
VENDOR_CONTEXT = {
    "microsoft": "enterprise and government endpoints and servers",
    "cisco": "network infrastructure, including carrier and government networks",
    "fortinet": "network perimeter and VPN gateways",
    "paloaltonetworks": "network perimeter and VPN gateways",
    "ivanti": "remote-access and endpoint-management systems",
    "citrix": "remote-access and application-delivery systems",
    "vmware": "virtualised data-centre infrastructure",
    "apache": "widely deployed web and application servers",
    "adobe": "document and creative software on user desktops",
    "google": "browsers and mobile devices used by the general public",
    "apple": "consumer devices",
    "linux": "servers, cloud workloads and embedded devices",
    "siemens": "industrial control and operational technology",
    "schneider-electric": "industrial control and operational technology",
    "wordpress": "public-facing websites",
    "oracle": "enterprise databases and business applications",
    "sap": "enterprise business applications",
}

AV_TEXT = {"NETWORK": "over the internet", "ADJACENT_NETWORK": "from the same network",
           "LOCAL": "with local access", "PHYSICAL": "with physical access"}


def _s(v):
    if v is None or (isinstance(v, float) and v != v):
        return ""
    return str(v).strip()


def _f(v):
    try:
        x = float(v)
        return None if x != x else x
    except (TypeError, ValueError):
        return None


def clean(o):
    """Make a structure JSON-safe (NaN/inf -> None, numpy -> python)."""
    if isinstance(o, dict):
        return {k: clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [clean(v) for v in o]
    if hasattr(o, "tolist"):  # numpy arrays and numpy scalars
        return clean(o.tolist())
    if isinstance(o, float) and (o != o or o in (float("inf"), float("-inf"))):
        return None
    return o


def _footprint(n_products, n_cpes):
    n = n_products or 0
    if n == 0 and n_cpes:
        n = n_cpes
    if n == 0:
        return "unknown"
    if n < 5:
        return "narrow"
    if n < 50:
        return "moderate"
    if n < 500:
        return "broad"
    return "very broad"


def build_impact(store, cve_ids):
    ids = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    if not ids:
        return []

    base = store.query("""
        SELECT v.cve_id, v.description, v.cvss3_score, v.cvss3_severity, v.cvss4_score,
               v.cvss4_severity, v.cvss2_score, v.cvss2_severity, v.cwe_ids, v.attack_vector,
               v.privileges_required, v.user_interaction, v.scope, v.confidentiality_impact,
               v.integrity_impact, v.availability_impact, v.n_references, v.n_affected_cpes,
               TRY_CAST(s.epss AS DOUBLE) AS epss,
               COALESCE(TRY_CAST(s.exploitdb AS INT),0) + COALESCE(TRY_CAST(s.metasploit AS INT),0)
                 + COALESCE(TRY_CAST(s.nuclei AS INT),0) + COALESCE(TRY_CAST(s.poc_github AS INT),0)
                 AS exploit_signals
        FROM vulnerabilities v
        LEFT JOIN scoreboard s ON upper(v.cve_id) = upper(s.cve_id)
        WHERE list_contains(?::VARCHAR[], upper(v.cve_id))
    """, [ids])

    kev_df = store.query("""
        SELECT upper(cve_id) AS cve_id, MIN(date_added) AS date_added,
               bool_or(lower(trim(known_ransomware_use)) = 'known') AS ransomware
        FROM known_exploited WHERE list_contains(?::VARCHAR[], upper(cve_id)) GROUP BY 1
    """, [ids])
    kev = {r["cve_id"]: r for r in kev_df.to_dict("records")}

    prod_df = store.query("""
        SELECT upper(cve_id) AS cve_id, list(DISTINCT lower(trim(vendor))) AS vendors,
               COUNT(DISTINCT lower(trim(vendor)) || '/' || lower(trim(product))) AS n_products
        FROM affected_products
        WHERE upper(trim(vulnerable)) = 'Y' AND list_contains(?::VARCHAR[], upper(cve_id)) GROUP BY 1
    """, [ids])
    prods = {r["cve_id"]: r for r in prod_df.to_dict("records")}

    refs = {}
    refs_file = store.path / "references.csv"
    if refs_file.is_file():
        # Read on demand: the API has little memory to spare for every reference URL.
        ref_df = store.query("""
            SELECT upper(cve_id) AS cve_id, COUNT(*) AS n_refs,
                   COUNT(*) FILTER (WHERE lower(coalesce(domain,'')) LIKE '%github.com%'
                       OR lower(coalesce(domain,'')) LIKE '%exploit-db.com%'
                       OR lower(coalesce(domain,'')) LIKE '%packetstormsecurity%'
                       OR lower(coalesce(domain,'')) LIKE '%seclists.org%') AS n_exploit_refs,
                   list(DISTINCT domain) AS domains
            FROM read_csv(?, delim=',', quote='"', escape='"', header=true, all_varchar=true,
                          strict_mode=true, ignore_errors=false)
            WHERE list_contains(?::VARCHAR[], upper(cve_id)) GROUP BY 1
        """, [str(refs_file), ids])
        refs = {r["cve_id"]: r for r in ref_df.to_dict("records")}

    cwe_names = {}
    if "weakness_types" in store.tables:
        w = store.query("SELECT cwe_id, name FROM weakness_types")
        cwe_names = dict(zip(w["cwe_id"], w["name"]))

    out = []
    for r in base.to_dict("records"):
        cid = _s(r["cve_id"]).upper()
        desc = _s(r["description"])
        cwe_ids = [c.strip() for c in _s(r["cwe_ids"]).split(";") if c.strip()]
        names = [cwe_names[c] for c in cwe_ids if c in cwe_names]

        harms = {}
        if _s(r["confidentiality_impact"]) == "HIGH":
            harms["data_exposure"] = "sensitive data can be fully disclosed"
        if _s(r["integrity_impact"]) == "HIGH":
            harms["data_tampering"] = "data or systems can be modified"
        if _s(r["availability_impact"]) == "HIGH":
            harms["service_disruption"] = "the service can be taken offline"
        for n in names:
            for kw, cat, effect in HARM_DICT:
                if kw in n.lower():
                    harms[cat] = effect
        for pattern, cat, effect in DESC_RULES:
            if re.search(pattern, desc, re.I):
                harms[cat] = effect

        severity = next((_s(r[k]) for k in ("cvss3_severity", "cvss4_severity", "cvss2_severity") if _s(r[k])), "UNKNOWN")
        score = next((_f(r[k]) for k in ("cvss3_score", "cvss4_score", "cvss2_score") if _f(r[k]) is not None), None)

        av, pr, ui = _s(r["attack_vector"]), _s(r["privileges_required"]), _s(r["user_interaction"])
        no_login, no_click = pr in ("", "NONE"), ui in ("", "NONE")
        if not av:
            ease = "unknown"
        elif av == "NETWORK" and no_login and no_click:
            ease = "easy"
        elif no_login or no_click:
            ease = "moderate"
        else:
            ease = "harder"

        p = prods.get(cid)
        vendors = [v for v in (list(p["vendors"]) if p else []) if v]
        n_products = int(p["n_products"]) if p else 0
        n_cpes = int(_f(r["n_affected_cpes"]) or 0)
        contexts = sorted({VENDOR_CONTEXT[v] for v in vendors if v in VENDOR_CONTEXT})
        k = kev.get(cid)
        ref = refs.get(cid)
        ransomware = bool(k["ransomware"]) if k else False

        parts = []
        if av:
            parts.append(f"Exploitable {AV_TEXT.get(av, 'by an unspecified route')}"
                         + (" without a login" if no_login else " with an account")
                         + ("" if no_click else ", needing a victim to act") + ".")
        if harms:
            parts.append("Possible effects: " + "; ".join(sorted(set(harms.values()))) + ".")
        if _s(r["scope"]) == "CHANGED":
            parts.append("Impact can extend beyond the vulnerable component.")
        if contexts:
            parts.append("Affected products sit in: " + "; ".join(contexts[:3]) + ".")
        if k:
            parts.append("Confirmed exploited in the wild (CISA KEV)"
                         + (", including by ransomware operators." if ransomware else "."))
        elif int(r["exploit_signals"] or 0) > 0:
            parts.append("Public exploit code or scanners exist.")
        if ref and ref["n_exploit_refs"]:
            parts.append(f"{int(ref['n_exploit_refs'])} reference(s) point to code or write-ups hosting technical detail.")
        if not parts:
            parts.append("Too little structured data to describe impact; see the description.")

        out.append({
            "cve_id": cid, "severity": severity, "score": score, "epss": _f(r["epss"]),
            "weaknesses": names, "harm_categories": sorted(harms), "exploit_ease": ease,
            "footprint": _footprint(n_products, n_cpes), "n_products": n_products,
            "n_affected_cpes": n_cpes, "vendors": vendors[:10], "contexts": contexts,
            "in_kev": bool(k), "ransomware_use": ransomware, "exploit_code": int(r["exploit_signals"] or 0) > 0,
            "n_references": int(ref["n_refs"]) if ref else int(_f(r["n_references"]) or 0),
            "ref_domains": sorted(d for d in (list(ref["domains"]) if ref else []) if d)[:5],
            "description": desc, "narrative": " ".join(parts),
        })
    out.sort(key=lambda x: (not x["in_kev"], -(x["epss"] or 0)))
    return out


def _counts(counter, n=8):
    return [{"label": k, "count": v} for k, v in counter.most_common(n)]


def summarize(rows, requested):
    n = len(rows)
    if n == 0:
        return {"headline": "None of the CVEs in top500.csv matched vulnerabilities.csv.",
                "kev": 0, "easy": 0, "exploit_code": 0, "critical_high": 0, "no_products": 0,
                "harm": [], "severity": [], "footprint": [], "vendors": [], "contexts": [], "weaknesses": []}
    harm = Counter(h for r in rows for h in r["harm_categories"])
    kev = sum(r["in_kev"] for r in rows)
    easy = sum(r["exploit_ease"] == "easy" for r in rows)
    exploit_code = sum(r["exploit_code"] for r in rows)
    critical_high = sum(r["severity"] in ("CRITICAL", "HIGH") for r in rows)
    no_products = sum(r["footprint"] == "unknown" for r in rows)
    top_harm = harm.most_common(1)
    headline = (f"{n} of {requested} CVEs matched dataset records. {exploit_code} have public exploit code and "
                f"{easy} can be attacked remotely with no login or user action."
                + (f" Confirmed exploited (CISA KEV): {kev}." if kev else "")
                + (f" The most common potential consequence is {top_harm[0][0].replace('_', ' ')} ({top_harm[0][1]} CVEs)."
                   if top_harm else ""))
    return {
        "headline": headline, "kev": kev, "easy": easy, "exploit_code": exploit_code,
        "critical_high": critical_high, "no_products": no_products,
        # Not capped: this list also fills the page's consequence filter.
        "harm": _counts(harm, None), "severity": _counts(Counter(r["severity"] for r in rows)),
        "footprint": _counts(Counter(r["footprint"] for r in rows)),
        "vendors": _counts(Counter(v for r in rows for v in r["vendors"])),
        "contexts": _counts(Counter(c for r in rows for c in r["contexts"])),
        "weaknesses": _counts(Counter(w for r in rows for w in r["weaknesses"])),
    }


def top500_impact(store, path):
    df = pd.read_csv(Path(path), dtype=str, encoding="utf-8-sig")
    df.columns = [c.strip().lower() for c in df.columns]
    if "cve_id" not in df.columns:
        raise ValueError("top500.csv needs a cve_id column")
    ids = list(dict.fromkeys(i.strip().upper() for i in df["cve_id"].dropna() if CVE_RE.match(i.strip())))
    ids = ids[:1000]
    rows = build_impact(store, ids)
    found = {r["cve_id"] for r in rows}
    kev_through = store.query("SELECT max(date_added) AS last_added FROM known_exploited")["last_added"].iloc[0]
    return clean({
        "source": Path(path).name, "requested": len(ids), "matched": len(rows),
        "missing": [i for i in ids if i not in found][:50], "kev_through": _s(kev_through) or None,
        "summary": summarize(rows, len(ids)), "rows": rows,
    })
