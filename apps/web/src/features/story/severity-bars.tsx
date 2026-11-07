import { type ReactNode, useRef } from "react";

import {
  DataTable,
  count,
  percent,
  useChartTooltip,
  useElementWidth,
  useInView,
} from "./chart-kit";

type Row = { label: string; published: number; listed: number };

const ROW = 28;
const LABEL = 72;
const VALUE = 64;

/** Rounded data end, square at the baseline. */
function barPath(x: number, y: number, width: number, height: number, r = 4) {
  if (width < r) return `M${x} ${y}h${width}v${height}h${-width}z`;
  return `M${x} ${y}h${width - r}q${r} 0 ${r} ${r}v${height - 2 * r}q0 ${r} ${-r} ${r}h${-(width - r)}z`;
}

/** Share of each CVSS 3 severity that reached the KEV list. */
export function SeverityBars({ rows, caption }: { rows: Row[]; caption?: ReactNode }) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const inView = useInView(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const height = rows.length * ROW;
  const maxRate = Math.max(...rows.map((row) => row.listed / row.published));
  const span = Math.max(0, width - LABEL - VALUE);

  return (
    <>
      <div ref={box} className="relative w-full" style={{ height }}>
        {width > 0 && (
          <svg width={width} height={height} className="block">
            {rows.map((row, index) => {
              const rate = row.listed / row.published;
              const barWidth = Math.max(2, (rate / maxRate) * span);
              const y = index * ROW;
              const strong = index === rows.length - 1;
              const text = strong ? "fill-foreground font-semibold" : "fill-muted-foreground";
              const detail = `${row.label}: ${count(row.listed)} of ${count(row.published)} listed (${percent(rate, 2)})`;
              return (
                <g key={row.label} {...markProps(detail, detail)}>
                  <rect x={0} y={y} width={width} height={ROW} fill="transparent" />
                  <text x={0} y={y + 18} className={`text-xs ${text}`}>
                    {row.label}
                  </text>
                  <path
                    d={barPath(LABEL, y + 5, barWidth, 18)}
                    className="fill-(--story-s1) transition-transform duration-700 ease-out motion-reduce:transition-none"
                    style={{
                      transformOrigin: `${LABEL}px 0`,
                      transform: inView ? "scaleX(1)" : "scaleX(0)",
                      transitionDelay: `${index * 90}ms`,
                    }}
                  />
                  <text
                    x={LABEL + barWidth + 8}
                    y={y + 18}
                    className={`text-xs tabular-nums ${text}`}
                  >
                    {percent(rate, 2)}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
        {tooltip}
      </div>
      {caption}
      <DataTable
        head={["Severity", "Listed", "Published", "Share listed"]}
        rows={rows.map((row) => [
          row.label,
          count(row.listed),
          count(row.published),
          percent(row.listed / row.published, 2),
        ])}
      />
    </>
  );
}
