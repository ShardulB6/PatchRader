import type { ReactNode } from "react";

import { count, percent } from "./chart-kit";
import story from "./story-data.json";

// Small charts that sit under each headline number in section 1. The highlighted share is always
// --story-s1; everything else is muted, so the eye goes to the number the text is about.

const Caption = ({ children }: { children: ReactNode }) => (
  <div className="mt-1 flex justify-between gap-2 text-[11px] text-muted-foreground tabular-nums">
    {children}
  </div>
);

/** Two labeled bars on a shared scale, the second highlighted. */
export function PairBars({
  rows,
  max,
  format,
  label,
}: {
  rows: [string, number][];
  max: number;
  format: (v: number) => string;
  label: string;
}) {
  return (
    <div className="mt-2 grid gap-1.5" role="img" aria-label={label}>
      {rows.map(([name, v], i) => {
        const strong = i === rows.length - 1;
        return (
          <div
            key={name}
            className="grid grid-cols-[5.5rem_minmax(0,1fr)_3.5rem] items-center gap-2"
          >
            <span className="text-[11px] text-muted-foreground">{name}</span>
            <span className="h-2.5 rounded-r bg-muted">
              <span
                className={`block h-full rounded-r ${strong ? "bg-(--story-s1)" : "bg-muted-foreground/50"}`}
                style={{ width: `${(100 * v) / max}%` }}
              />
            </span>
            <span
              className={`text-right text-xs tabular-nums ${strong ? "font-semibold" : "text-muted-foreground"}`}
            >
              {format(v)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/** 100 squares, `filled` of them highlighted. */
export function Waffle({ filled, label }: { filled: number; label: string }) {
  return (
    <div className="mt-2" role="img" aria-label={label}>
      <div className="grid max-w-56 grid-cols-20 gap-0.5">
        {Array.from({ length: 100 }, (_, i) => (
          <span
            key={i}
            className={`aspect-square rounded-[2px] ${i < filled ? "bg-(--story-s1)" : "bg-muted-foreground/25"}`}
          />
        ))}
      </div>
      <Caption>
        <span>
          <span className="mr-1 inline-block size-2 rounded-[2px] bg-(--story-s1)" />
          fully fixed
        </span>
        <span>
          <span className="mr-1 inline-block size-2 rounded-[2px] bg-muted-foreground/25" />
          still open: {100 - filled}%
        </span>
      </Caption>
    </div>
  );
}

/** One highlighted dot among `total`. */
export function NeedleDots({ total, label }: { total: number; label: string }) {
  const at = Math.floor(total * 0.62);
  return (
    <div className="mt-2" role="img" aria-label={label}>
      <div className="flex flex-wrap gap-[3px]">
        {Array.from({ length: total }, (_, i) => (
          <span
            key={i}
            className={`size-[5px] rounded-full ${i === at ? "bg-(--story-s1) outline-2 outline-offset-1 outline-(--story-s1)" : "bg-muted-foreground/30"}`}
          />
        ))}
      </div>
      <Caption>
        <span>Each dot is one CVE; one of {total} reached KEV</span>
      </Caption>
    </div>
  );
}

/** A 100% bar split into labeled segments; `highlight` names the segment the text is about. */
export function SplitBar({
  parts,
  highlight,
  label,
}: {
  parts: { name: string; n: number }[];
  highlight: string;
  label: string;
}) {
  const total = parts.reduce((s, p) => s + p.n, 0);
  return (
    <div className="mt-2" role="img" aria-label={label}>
      <div className="flex h-3 gap-0.5 overflow-hidden rounded">
        {parts.map((p) => (
          <span
            key={p.name}
            className={p.name === highlight ? "bg-(--story-s1)" : "bg-muted-foreground/40"}
            style={{ width: `${(100 * p.n) / total}%` }}
          />
        ))}
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground tabular-nums">
        {parts.map((p) => (
          <span
            key={p.name}
            className={p.name === highlight ? "font-semibold text-foreground" : undefined}
          >
            {p.name} {percent(p.n / total)}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Median EPSS by month relative to the KEV listing month. */
export function EpssSpark({ label }: { label: string }) {
  const pts = story.epss.medians;
  const W = 300;
  const H = 64;
  const pad = 6;
  const max = Math.max(...pts.map((p) => p.median));
  const x = (i: number) => pad + (i / (pts.length - 1)) * (W - 2 * pad);
  const y = (v: number) => H - pad - (v / max) * (H - 2 * pad);
  const d = pts
    .map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p.median).toFixed(1)}`)
    .join("");
  const at = pts.findIndex((p) => p.offset === 0);
  return (
    <div className="mt-2" role="img" aria-label={label}>
      <svg viewBox={`0 0 ${W} ${H}`} className="block h-16 w-full" preserveAspectRatio="none">
        <line
          x1={x(at)}
          x2={x(at)}
          y1={0}
          y2={H}
          className="stroke-border"
          strokeDasharray="3 3"
          vectorEffect="non-scaling-stroke"
        />
        <path
          d={d}
          fill="none"
          className="stroke-(--story-s1)"
          strokeWidth={2}
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <div className="relative mt-1 h-4 text-[11px] text-muted-foreground">
        <span className="absolute left-0">6 months before</span>
        <span
          className="absolute -translate-x-1/2 font-semibold text-foreground"
          style={{ left: `${(100 * x(at)) / W}%` }}
        >
          listed
        </span>
        <span className="absolute right-0">+2</span>
      </div>
    </div>
  );
}

// ---- Data from the story page's numbers (scripts/build_story_data.py) ----------------------------

const listedBySeverity = story.severity.reduce(
  (acc, row) => {
    if (row.label === "Critical") acc.critical += row.listed;
    else acc.other += row.listed;
    return acc;
  },
  { critical: 0, other: 0 },
);

export const SEVERITY_PARTS = [
  { name: "Not Critical", n: listedBySeverity.other },
  { name: "Critical", n: listedBySeverity.critical },
];

const lagCount = (labels: string[]) =>
  story.lag.bins.filter((b) => labels.includes(b.label)).reduce((s, b) => s + b.count, 0);

export const LAG_PARTS = [
  { name: "Within 30 days", n: lagCount(["Same day or earlier", "1 to 7 days", "8 to 30 days"]) },
  { name: "1–6 months", n: lagCount(["31 to 180 days"]) },
  { name: "Over 6 months", n: lagCount(["181 to 365 days", "1 to 3 years", "Over 3 years"]) },
];

export const HAYSTACK = story.haystack;
export { count };
