import { type ReactNode, useRef } from "react";

import { DataTable, percent, useChartTooltip, useElementWidth, useInView } from "./chart-kit";

type Bin = { label: string; short: string; count: number };

const HEIGHT = 190;
const LEFT = 32;
const TOP = 26;
const BOTTOM = 24;
// The first two bins (a week or less) and the last two (over a year) carry the story.
const EMPHASIS = new Set([0, 1, 5, 6]);

function columnPath(x: number, base: number, width: number, height: number, r = 4) {
  if (height < r) return `M${x} ${base}v${-height}h${width}v${height}z`;
  return `M${x} ${base}v${-(height - r)}q0 ${-r} ${r} ${-r}h${width - 2 * r}q${r} 0 ${r} ${r}v${height - r}z`;
}

/** Days from NIST publication to KEV listing. */
export function LagColumns({
  bins,
  total,
  caption,
}: {
  bins: Bin[];
  total: number;
  caption?: ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const inView = useInView(box);
  const { tooltip, markProps } = useChartTooltip(box);

  const base = HEIGHT - BOTTOM;
  const plot = base - TOP;
  const max = Math.ceil(Math.max(...bins.map((bin) => bin.count)) / 50) * 50;
  const band = (width - LEFT) / bins.length;
  const barWidth = Math.min(24, band - 6);
  const narrow = width < 480;
  const firstWeek = (bins[0]!.count + bins[1]!.count) / total;
  const overAYear = (bins[5]!.count + bins[6]!.count) / total;

  return (
    <>
      <div ref={box} className="relative w-full" style={{ height: HEIGHT }}>
        {width > 0 && (
          <svg width={width} height={HEIGHT} className="block">
            {[0, max / 2, max].map((tick) => (
              <g key={tick}>
                <line
                  x1={LEFT}
                  x2={width}
                  y1={base - (tick / max) * plot}
                  y2={base - (tick / max) * plot}
                  className={tick ? "stroke-border" : "stroke-muted-foreground/50"}
                />
                <text
                  x={LEFT - 6}
                  y={base - (tick / max) * plot + 4}
                  textAnchor="end"
                  className="fill-muted-foreground text-[11px] tabular-nums"
                >
                  {tick}
                </text>
              </g>
            ))}
            <text x={LEFT + 4} y={12} className="fill-foreground text-xs font-semibold">
              {percent(firstWeek)} within a week
            </text>
            <text
              x={width - 2}
              y={12}
              textAnchor="end"
              className="fill-foreground text-xs font-semibold"
            >
              {percent(overAYear)} over a year
            </text>
            {bins.map((bin, index) => {
              const x = LEFT + band * index + (band - barWidth) / 2;
              const detail = `${bin.label}: ${bin.count} of ${total} (${percent(bin.count / total)})`;
              return (
                <g key={bin.label} {...markProps(detail, detail)}>
                  <rect
                    x={LEFT + band * index}
                    y={TOP}
                    width={band}
                    height={plot + BOTTOM}
                    fill="transparent"
                  />
                  <path
                    d={columnPath(x, base, barWidth, (bin.count / max) * plot)}
                    className={`transition-transform duration-700 ease-out motion-reduce:transition-none ${
                      EMPHASIS.has(index) ? "fill-(--story-s1)" : "fill-muted-foreground/45"
                    }`}
                    style={{
                      transformOrigin: `0 ${base}px`,
                      transform: inView ? "scaleY(1)" : "scaleY(0)",
                      transitionDelay: `${index * 70}ms`,
                    }}
                  />
                  <text
                    x={x + barWidth / 2}
                    y={HEIGHT - 7}
                    textAnchor="middle"
                    className="fill-muted-foreground text-[11px]"
                  >
                    {narrow ? bin.short.replace(" d", "").replace(" y", "y") : bin.short}
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
        head={["Publication to listing", "Listings", "Share"]}
        rows={bins.map((bin) => [bin.label, bin.count, percent(bin.count / total)])}
      />
    </>
  );
}
