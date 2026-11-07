#!/usr/bin/env python3
"""Compute the numbers behind the /story page from data/ and write them as JSON.

Usage: python3 scripts/build_story_data.py [path to data directory]

Uses only the standard library, like fetch_data.py. Run fetch_data.py first.
The output is committed, so the page needs neither the dataset nor a database.
"""

import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "apps" / "web" / "src" / "features" / "story" / "story-data.json"
EXPLOIT_CODE = ("exploitdb", "metasploit", "nuclei", "poc_github")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
# Days from publication to KEV listing. The bins have unequal widths on purpose:
# they separate listings that come right away from ones that come years later.
LAG_BINS = (
    ("Same day or earlier", "≤0 d", None, 0),
    ("1 to 7 days", "1–7 d", 1, 7),
    ("8 to 30 days", "8–30 d", 8, 30),
    ("31 to 180 days", "31–180 d", 31, 180),
    ("181 to 365 days", "181–365 d", 181, 365),
    ("1 to 3 years", "1–3 y", 366, 1095),
    ("Over 3 years", ">3 y", 1096, None),
)
LOUD_EPSS = 0.1


def parse_date(text):
    return date.fromisoformat(text[:10])


def month_index(text):
    """Months since year 0 for a YYYY-MM or YYYY-MM-DD string."""
    return int(text[:4]) * 12 + int(text[5:7]) - 1


def month_of(day):
    return day.year * 12 + day.month - 1


def month_end(index):
    year, month = divmod(index, 12)
    return date(year + (month == 11), (month + 1) % 12 + 1, 1) - timedelta(days=1)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as handle:
        yield from csv.DictReader(handle)


def main():
    data = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data"
    csv.field_size_limit(2**31 - 1)

    kev = {row["cve_id"]: parse_date(row["date_added"]) for row in read_csv(data / "known_exploited.csv")}
    vulns = {}
    for row in read_csv(data / "vulnerabilities.csv"):
        vulns[row["cve_id"]] = (parse_date(row["published"]), row["cvss3_severity"], row["cwe_ids"])

    # Signals for listed vulnerabilities only, keyed by month: (epss or None, has exploit code).
    signals = defaultdict(dict)
    unlisted_dec_2024 = [0, 0]  # [all, loud], for scale in the visibility beat
    dec_2024 = month_index("2024-12")
    for name in ("exploit_signals_2024.csv", "exploit_signals_2025.csv"):
        for row in read_csv(data / name):
            epss = float(row["epss"]) if row["epss"] else None
            code = any(row[column] == "1" for column in EXPLOIT_CODE)
            month = month_index(row["month"])
            if row["cve_id"] in kev:
                signals[row["cve_id"]][month] = (epss, code)
            # Count only real vulnerabilities published by then, not rejected or reserved IDs.
            known = row["cve_id"] in vulns and vulns[row["cve_id"]][0] <= month_end(dec_2024)
            if month == dec_2024 and known and row["in_kev"] != "1":
                unlisted_dec_2024[0] += 1
                unlisted_dec_2024[1] += code or (epss or 0) >= LOUD_EPSS

    # Beat 1: one year's haystack. KEV in this dataset ends on December 31, 2025.
    published_2025 = sum(1 for published, _, _ in vulns.values() if published.year == 2025)
    listed_2025 = sum(1 for cve in kev if cve in vulns and vulns[cve][0].year == 2025)
    published_2026 = sum(1 for published, _, _ in vulns.values() if published.year == 2026)

    # Beat 2: share listed by CVSS 3 severity, and two weakness types for contrast.
    severity = {name: [0, 0] for name in SEVERITIES}
    weakness = {"CWE-79": [0, 0], "CWE-843": [0, 0]}
    for cve, (published, sev, cwes) in vulns.items():
        if published.year > 2025:
            continue
        listed = cve in kev
        if sev in severity:
            severity[sev][0] += 1
            severity[sev][1] += listed
        for cwe in set(cwes.split(";")) & weakness.keys():
            weakness[cwe][0] += 1
            weakness[cwe][1] += listed

    # Beat 3a: days from publication to listing, for listings in 2024 and 2025.
    lags = [(added - vulns[cve][0]).days for cve, added in kev.items() if added.year in (2024, 2025) and cve in vulns]
    lag_bins = []
    for label, short, low, high in LAG_BINS:
        count = sum(1 for lag in lags if (low is None or lag >= low) and (high is None or lag <= high))
        lag_bins.append({"label": label, "short": short, "count": count})
    assert sum(b["count"] for b in lag_bins) == len(lags)

    # Beat 3b: what was visible at the last month-end before each listing.
    states = Counter()
    first, last = month_index("2024-02"), month_index("2025-12")
    for cve, added in kev.items():
        listed_month = month_of(added)
        if not first <= listed_month <= last or cve not in vulns:
            continue
        before = listed_month - 1
        row = signals[cve].get(before)
        if vulns[cve][0] > month_end(before):
            states["notPublished"] += 1
        elif row is None:
            states["noData"] += 1
        elif row[1] or (row[0] is not None and row[0] >= LOUD_EPSS):
            states["loud"] += 1
        else:
            states["quiet"] += 1

    # Beat 4: median EPSS around the listing month, for vulnerabilities published before
    # month -6 began, so each has a score for every month shown. Listings from July to December 2024 keep months -6 to +2
    # inside one EPSS model; EPSS changed its model in March 2025.
    def epss_cohort(start, end):
        by_offset = defaultdict(list)
        size = 0
        for cve, added in kev.items():
            listed_month = month_of(added)
            if not month_index(start) <= listed_month <= month_index(end) or cve not in vulns:
                continue
            if vulns[cve][0] > month_end(listed_month - 7):
                continue
            size += 1
            for offset in range(-6, 3):
                row = signals[cve].get(listed_month + offset)
                if row and row[0] is not None:
                    by_offset[offset].append(row[0])
        medians = [{"offset": k, "median": round(statistics.median(by_offset[k]), 4), "n": len(by_offset[k])} for k in range(-6, 3)]
        return size, medians

    cohort_size, medians = epss_cohort("2024-07", "2024-12")
    counter_size, counter_medians = epss_cohort("2025-10", "2025-10")

    story = {
        "source": "IBM track dataset, data-v1 release. Built by scripts/build_story_data.py.",
        "haystack": {"year": 2025, "published": published_2025, "listed": listed_2025, "published2026": published_2026},
        "severity": [{"label": name.title(), "published": n, "listed": k} for name, (n, k) in severity.items()],
        "weakness": {
            "xss": {"published": weakness["CWE-79"][0], "listed": weakness["CWE-79"][1]},
            "typeConfusion": {"published": weakness["CWE-843"][0], "listed": weakness["CWE-843"][1]},
        },
        "lag": {"total": len(lags), "bins": lag_bins},
        "visibility": {
            "from": "2024-02",
            "to": "2025-12",
            "total": sum(states.values()),
            "notPublished": states["notPublished"],
            "noData": states["noData"],
            "quiet": states["quiet"],
            "loud": states["loud"],
            "unlistedLoudShareDec2024": round(unlisted_dec_2024[1] / unlisted_dec_2024[0], 4),
        },
        "epss": {
            "from": "2024-07",
            "to": "2024-12",
            "cohort": cohort_size,
            "medians": medians,
            "counterexample": {
                "month": "2025-10",
                "cohort": counter_size,
                "low": min(m["median"] for m in counter_medians),
                "high": max(m["median"] for m in counter_medians),
            },
        },
    }
    OUT.write_text(json.dumps(story, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
