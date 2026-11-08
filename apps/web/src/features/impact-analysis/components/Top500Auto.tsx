import { Button } from "@PatchRader/ui/components/button";
import { useEffect, useMemo, useState } from "react";
import { getTop500Impact, type Top500Impact } from "../../../lib/ai-client";
import { DataTable, Verdict } from "../../ai/answer-cards/answer-view";
import { count } from "../../ai/answer-cards/read";
import { Bars } from "../../ai/answer-chart";
import { ImpactList, pretty } from "./ImpactList";

/** Weakness names end with their common name in quotes: "... ('Path Traversal')". */
const weaknessName = (name: string) => name.match(/\('([^']+)'\)$/)?.[1] ?? name;

function Chart({
  title,
  items,
  total,
  name = pretty,
  className,
}: {
  title: string;
  items: { label: string; count: number }[];
  total: number;
  name?: (label: string) => string;
  className?: string;
}) {
  if (items.length === 0) return null;
  const points = items.map((item) => ({
    label: name(item.label),
    value: item.count,
    detail: `${pretty(item.label)}: ${count(item.count)} of ${count(total)} CVEs`,
  }));
  return (
    <div className={className}>
      <h3 className="text-sm font-semibold">{title}</h3>
      <Bars points={points} format={count} fitLabels />
    </div>
  );
}

export default function Top500Auto() {
  const [data, setData] = useState<Top500Impact | null>(null);
  const [status, setStatus] = useState<"loading" | "missing" | "error" | "ready">("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [harm, setHarm] = useState("all");
  const [shown, setShown] = useState(25);

  useEffect(() => {
    getTop500Impact()
      .then((result) => {
        setData(result);
        setStatus(result ? "ready" : "missing");
      })
      .catch((error: unknown) => {
        setErrorMessage(error instanceof Error ? error.message : "");
        setStatus("error");
      });
  }, []);

  const rows = useMemo(
    () => (data?.rows ?? []).filter((r) => harm === "all" || r.harm_categories.includes(harm)),
    [data, harm],
  );

  if (status === "loading") {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        Looking for top500.csv…
      </p>
    );
  }
  if (status === "missing") {
    return (
      <p className="text-xs text-muted-foreground">
        No ranking file was found at <code>outputs/top500.csv</code>, so there is nothing to analyze
        yet.
      </p>
    );
  }
  if (status === "error" || !data) {
    return (
      <p role="alert" className="text-sm text-destructive">
        Could not analyze top500.csv. {errorMessage}
      </p>
    );
  }

  const s = data.summary;
  const tiles: [string, number][] = [
    ["Public exploit code", s.exploit_code],
    ["Remote, no login or click", s.easy],
    ["Critical or high severity", s.critical_high],
    ["No product data yet", s.no_products],
  ];
  const tableRows = rows.map((r) => ({
    CVE: r.cve_id,
    Severity: r.severity,
    Score: r.score,
    EPSS: r.epss,
    Ease: r.exploit_ease,
    Footprint: r.footprint,
    "Exploit code": r.exploit_code ? "Yes" : "No",
    Consequences: r.harm_categories.map(pretty).join(", "),
  }));

  return (
    <section
      className="space-y-5 rounded-lg border bg-card p-4 text-sm"
      aria-labelledby="auto-heading"
    >
      <div className="space-y-2">
        <h2 id="auto-heading" className="text-lg font-semibold">
          Automatic analysis of {data.source}
        </h2>
        <Verdict headline={s.headline} />
        {data.missing.length > 0 && (
          <p className="text-xs text-muted-foreground">
            {data.requested - data.matched} ID(s) were not found in vulnerabilities.csv, e.g.{" "}
            {data.missing.slice(0, 3).join(", ")}.
          </p>
        )}
        {s.kev === 0 && data.kev_through && (
          <p className="text-xs text-muted-foreground">
            The CISA KEV list in this dataset ends on {data.kev_through}, so it can't show whether
            these CVEs have been exploited since.
          </p>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {tiles.map(([label, value]) => (
          <div key={label} className="rounded-md border p-3">
            <p className="text-xl font-bold tabular-nums">{count(value)}</p>
            <p className="text-xs text-muted-foreground">{label}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-x-8 gap-y-6 lg:grid-cols-2">
        <Chart title="Potential consequences" items={s.harm} total={data.matched} />
        <Chart
          title="Most common weaknesses"
          items={s.weaknesses}
          total={data.matched}
          name={weaknessName}
        />
        <Chart
          title="Where affected products sit"
          items={s.contexts}
          total={data.matched}
          className="lg:col-span-2"
        />
      </div>

      <div>
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="text-sm font-semibold">
            {s.kev > 0
              ? "CVEs, known exploited first, then highest EPSS"
              : "CVEs, highest EPSS first"}
          </h3>
          <label className="text-xs">
            Filter by consequence
            <select
              className="ml-2 rounded border bg-background px-2 py-1"
              value={harm}
              onChange={(e) => {
                setHarm(e.target.value);
                setShown(25);
              }}
            >
              <option value="all">All</option>
              {s.harm.map((h) => (
                <option key={h.label} value={h.label}>
                  {pretty(h.label)} ({h.count})
                </option>
              ))}
            </select>
          </label>
        </div>

        <ImpactList rows={rows.slice(0, shown)} />

        {shown < rows.length && (
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <Button variant="outline" size="sm" onClick={() => setShown((n) => n + 25)}>
              Show 25 more
            </Button>
            <p className="text-xs text-muted-foreground">
              {count(rows.length - shown)} more, all listed in the data table below.
            </p>
          </div>
        )}

        <DataTable rows={tableRows} open={false} />
      </div>

      <p className="text-xs text-muted-foreground">
        Qualitative indicators derived from CVSS fields, weakness types, descriptions, product lists
        and references. Footprint counts affected products, not customers, and the sector and
        consequence mappings are heuristics, not confirmed damage.
      </p>
    </section>
  );
}
