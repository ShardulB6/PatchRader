import { Fragment, useEffect, useMemo, useState } from "react";
import { getTop500Impact, type Top500Impact } from "../../../lib/ai-client";

const pretty = (s: string) => s.replace(/_/g, " ");

function Bars({ title, items, total }: { title: string; items: { label: string; count: number }[]; total: number }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      <ul className="space-y-1.5">
        {items.map((item) => (
          <li key={item.label} className="text-xs">
            <div className="flex justify-between gap-2">
              <span>{pretty(item.label)}</span>
              <span>{item.count}</span>
            </div>
            <div className="h-1.5 rounded bg-muted">
              <div
                className="h-1.5 rounded bg-sky-500"
                style={{ width: `${Math.min(100, (item.count / Math.max(total, 1)) * 100)}%` }}
              />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Top500Auto() {
  const [data, setData] = useState<Top500Impact | null>(null);
  const [status, setStatus] = useState<"loading" | "missing" | "error" | "ready">("loading");
  const [harm, setHarm] = useState("all");
  const [open, setOpen] = useState<string | null>(null);
  const [shown, setShown] = useState(25);

  useEffect(() => {
    getTop500Impact()
      .then((result) => {
        setData(result);
        setStatus(result ? "ready" : "missing");
      })
      .catch(() => setStatus("error"));
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
        Tip: put a top500.csv (one <code>cve_id</code> column) in the project root to see an automatic impact
        analysis here.
      </p>
    );
  }
  if (status === "error" || !data) {
    return (
      <p role="alert" className="text-sm text-red-500">
        Could not analyze top500.csv. Check that the API is running and look at its logs.
      </p>
    );
  }

  const s = data.summary;
  const tiles: [string, number][] = [
    ["Confirmed exploited (KEV)", s.kev],
    ["Remote, no login or click", s.easy],
    ["Ransomware-linked", s.ransomware],
    ["Broad footprint", s.broad],
  ];

  return (
    <section className="space-y-4 rounded-xl border p-5" aria-labelledby="auto-heading">
      <div>
        <h2 id="auto-heading" className="text-lg font-semibold">
          Automatic analysis of {data.source}
        </h2>
        <p className="mt-1 text-sm">{s.headline}</p>
        {data.missing.length > 0 && (
          <p className="mt-1 text-xs text-muted-foreground">
            {data.requested - data.matched} ID(s) were not found in vulnerabilities.csv, e.g.{" "}
            {data.missing.slice(0, 3).join(", ")}.
          </p>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {tiles.map(([label, value]) => (
          <div key={label} className="rounded-lg border p-3">
            <p className="text-2xl font-bold">{value}</p>
            <p className="text-xs text-muted-foreground">{label}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <Bars title="Potential consequences" items={s.harm} total={data.matched} />
        <Bars title="Where affected products sit" items={s.contexts} total={data.matched} />
        <Bars title="Most common weaknesses" items={s.weaknesses} total={data.matched} />
      </div>

      <div>
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

        <div className="mt-3 overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr>
                {["CVE", "Severity", "Ease", "Footprint", "KEV", "Consequences"].map((h) => (
                  <th key={h} className="border-b px-2 py-1">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, shown).map((r) => (
                <Fragment key={r.cve_id}>
                  <tr
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => setOpen(open === r.cve_id ? null : r.cve_id)}
                  >
                    <td className="border-b px-2 py-1 font-mono">{r.cve_id}</td>
                    <td className="border-b px-2 py-1">
                      {r.severity}
                      {r.score != null ? ` (${r.score})` : ""}
                    </td>
                    <td className="border-b px-2 py-1">{r.exploit_ease}</td>
                    <td className="border-b px-2 py-1">{r.footprint}</td>
                    <td className="border-b px-2 py-1">{r.in_kev ? "Yes" : "No"}</td>
                    <td className="border-b px-2 py-1">{r.harm_categories.map(pretty).join(", ") || "—"}</td>
                  </tr>
                  {open === r.cve_id && (
                    <tr>
                      <td colSpan={6} className="border-b bg-muted/30 px-3 py-2">
                        <p>{r.narrative}</p>
                        {r.weaknesses.length > 0 && (
                          <p className="mt-1 text-muted-foreground">Weaknesses: {r.weaknesses.join("; ")}</p>
                        )}
                        {r.vendors.length > 0 && (
                          <p className="mt-1 text-muted-foreground">Vendors: {r.vendors.join(", ")}</p>
                        )}
                        {r.description && <p className="mt-1 text-muted-foreground">{r.description}</p>}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>

        {shown < rows.length && (
          <button
            type="button"
            className="mt-3 rounded border px-3 py-1 text-xs"
            onClick={() => setShown((n) => n + 25)}
          >
            Show 25 more
          </button>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        Qualitative indicators derived from CVSS fields, weakness types, descriptions, product lists and references.
        Footprint counts affected products, not customers, and the sector and consequence mappings are heuristics, not
        confirmed damage.
      </p>
    </section>
  );
}
