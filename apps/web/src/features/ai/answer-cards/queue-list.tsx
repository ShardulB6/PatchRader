import type { ChatRow } from "../../../lib/ai-client";
import { count, EXPLOIT_COLUMNS, num, prose, text, vendorName } from "./read";
import { ExploitTags } from "./parts";

const SHOWN = 10;

/** The priority queue as a ranked list. Rows without a CVE ID or rank are skipped. */
export function QueueList({ rows }: { rows: ChatRow[] }) {
  const items = rows.flatMap((row) => {
    const id = text(row.cve_id);
    const rank = num(row.priority_rank);
    if (!id || rank === null) return [];
    const sources = EXPLOIT_COLUMNS.filter(([column]) => (num(row[column]) ?? 0) > 0).map(
      ([, name]) => name,
    );
    return [
      {
        id,
        rank,
        sources,
        epss: num(row.epss),
        vendor: text(row.vendor),
        description: prose(row.description),
      },
    ];
  });
  if (items.length === 0) return null;
  const hidden = items.length - SHOWN;

  return (
    <div className="mt-3">
      <ol className="divide-y rounded-md border">
        {items.slice(0, SHOWN).map((item) => (
          <li key={item.id} className="flex items-start gap-3 px-3 py-2">
            <span className="w-14 shrink-0 pt-0.5 text-right text-xs font-semibold text-muted-foreground tabular-nums">
              #{count(item.rank)}
            </span>
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="font-mono text-xs font-semibold">{item.id}</span>
                {item.vendor && (
                  <span className="text-xs text-muted-foreground">{vendorName(item.vendor)}</span>
                )}
                <ExploitTags sources={item.sources} />
              </div>
              {item.description && (
                <p className="truncate text-xs text-muted-foreground" title={item.description}>
                  {item.description}
                </p>
              )}
            </div>
            {item.epss !== null && (
              <span className="shrink-0 pt-0.5 text-xs tabular-nums">
                <span className="text-muted-foreground">EPSS </span>
                {item.epss.toFixed(3)}
              </span>
            )}
          </li>
        ))}
      </ol>
      {hidden > 0 && (
        <p className="mt-1 text-xs text-muted-foreground">
          {count(hidden)} more in the data table below.
        </p>
      )}
    </div>
  );
}
