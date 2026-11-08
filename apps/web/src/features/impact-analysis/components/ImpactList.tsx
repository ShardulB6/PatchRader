import type { ImpactRow } from "../../../lib/ai-client";
import { BLUE, Field, Tag } from "../../ai/answer-cards/parts";
import { num, prose, vendorName } from "../../ai/answer-cards/read";

/** "data_exposure" -> "Data exposure". */
export function pretty(value: string) {
  const words = value.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function ImpactItem({ row }: { row: ImpactRow }) {
  const vendor = row.vendors[0];
  const description = prose(row.description);
  // The API response isn't validated, so read numbers defensively, as the chat does.
  const epss = num(row.epss);
  const score = num(row.score);
  const severity = [row.severity && pretty(row.severity.toLowerCase()), score]
    .filter((part) => part !== null && part !== "" && part !== undefined)
    .join(" ");

  return (
    <li>
      <details className={`group ${BLUE}`}>
        <summary className="flex cursor-pointer list-none items-start gap-2 px-3 py-2 select-none hover:bg-muted/50 [&::-webkit-details-marker]:hidden">
          <span
            aria-hidden
            className="pt-0.5 text-xs text-muted-foreground transition-transform group-open:rotate-90 motion-reduce:transition-none"
          >
            ›
          </span>
          <span className="block min-w-0 flex-1 space-y-1">
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-mono text-xs font-semibold">{row.cve_id}</span>
              {vendor && (
                <span className="text-xs text-muted-foreground">{vendorName(vendor)}</span>
              )}
              {severity && <Tag>{severity}</Tag>}
              {row.exploit_code && <Tag tone="danger">Public exploit code</Tag>}
              {row.exploit_ease === "easy" && <Tag>Remote, no login or click</Tag>}
            </span>
            {description && (
              <span className="block truncate text-xs text-muted-foreground group-open:hidden">
                {description}
              </span>
            )}
          </span>
          {epss !== null && (
            <span className="shrink-0 pt-0.5 text-xs tabular-nums">
              <span className="text-muted-foreground">EPSS </span>
              {epss.toFixed(3)}
            </span>
          )}
        </summary>

        <div className="space-y-3 border-t bg-muted/20 px-3 py-3 sm:pl-7">
          <p className="text-xs leading-relaxed">{row.narrative}</p>
          <div className="grid gap-3 sm:grid-cols-2">
            {epss !== null && (
              <Field label="EPSS">
                {/* EPSS is a 0-1 probability, so the bar uses that scale. */}
                <div className="mb-1 h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-(--ai-blue)"
                    style={{ width: `${Math.min(100, Math.max(0, epss * 100))}%` }}
                  />
                </div>
                <span className="tabular-nums">{epss.toFixed(3)}</span>
              </Field>
            )}
            {row.harm_categories.length > 0 && (
              <Field label="Potential consequences">
                <span className="flex flex-wrap gap-1.5">
                  {row.harm_categories.map((harm) => (
                    <Tag key={harm}>{pretty(harm)}</Tag>
                  ))}
                </span>
              </Field>
            )}
            <Field label="Ease of exploitation">{pretty(row.exploit_ease)}</Field>
            <Field label="Footprint">{pretty(row.footprint)}</Field>
            {row.vendors.length > 0 && (
              <Field label="Vendors">{row.vendors.map(vendorName).join(", ")}</Field>
            )}
            {row.weaknesses.length > 0 && (
              <Field label="Weaknesses">{row.weaknesses.join("; ")}</Field>
            )}
          </div>
          {description && (
            <p className="text-xs leading-relaxed break-words text-muted-foreground">
              {description}
            </p>
          )}
        </div>
      </details>
    </li>
  );
}

/** CVEs as a list in the AI Analyst's style. Each row opens to show its full profile. */
export function ImpactList({ rows }: { rows: ImpactRow[] }) {
  if (rows.length === 0) {
    return <p className="mt-3 text-xs text-muted-foreground">No CVEs match this filter.</p>;
  }
  return (
    <ul className="mt-3 divide-y rounded-md border">
      {rows.map((row) => (
        <ImpactItem key={row.cve_id} row={row} />
      ))}
    </ul>
  );
}
