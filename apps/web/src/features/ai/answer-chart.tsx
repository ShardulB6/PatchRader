import { useRef } from "react";

import type { ChatRow } from "@/lib/ai-client";
import { count, useChartTooltip, useElementWidth } from "@/features/story/chart-kit";

type Point = { label: string; value: number; detail: string };
type Spec = {
  label: (row: ChatRow) => string;
  value: string;
  format: (value: number) => string;
  form: "bars" | "columns";
};

const vendor = (row: ChatRow) => String(row.vendor ?? "");
const plain = (value: number) => count(value);

/** Which answers get a chart, and which columns it plots. Others show only the table. */
const SPECS: Record<string, Spec> = {
  top_vendors: { label: vendor, value: "vulnerabilities", format: plain, form: "bars" },
  vendor_kev_rate: {
    label: vendor,
    value: "kev_rate_pct",
    format: (value) => `${value.toFixed(1)}%`,
    form: "bars",
  },
  kev_vendors: { label: vendor, value: "known_exploited", format: plain, form: "bars" },
  top_cwes: {
    label: (row) => String(row.cwe_id ?? ""),
    value: "vulnerabilities",
    format: plain,
    form: "bars",
  },
  ransomware: {
    label: (row) => String(row.ransomware_status ?? ""),
    value: "vulnerabilities",
    format: plain,
    form: "bars",
  },
  published_years: {
    label: (row) => String(row.year ?? ""),
    value: "vulnerabilities",
    format: plain,
    form: "columns",
  },
};

// The story page's validated series blue, light and dark.
const COLOR = "[--ai-bar:#2a78d6] dark:[--ai-bar:#3987e5]";

/** Rounded data end, square at the baseline. */
function barPath(x: number, y: number, width: number, height: number, r = 4) {
  if (width < r) return `M${x} ${y}h${width}v${height}h${-width}z`;
  return `M${x} ${y}h${width - r}q${r} 0 ${r} ${r}v${height - 2 * r}q0 ${r} ${-r} ${r}h${-(width - r)}z`;
}

function columnPath(x: number, y: number, width: number, height: number) {
  const r = Math.min(4, width / 2, height);
  return `M${x} ${y + height}v${-(height - r)}q0 ${-r} ${r} ${-r}h${width - 2 * r}q${r} 0 ${r} ${r}v${height - r}z`;
}

const short = (text: string, max = 18) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);

/** A one-series chart above the answer's table, for list answers. */
export function AnswerChart({ operation, rows }: { operation: string; rows: ChatRow[] }) {
  const spec = SPECS[operation];
  if (!spec || rows.length < 2) return null;
  const points: Point[] = rows
    .map((row) => {
      const value = Number(row[spec.value]);
      const label = spec.label(row);
      const name = operation === "top_cwes" && row.weakness ? `${label} ${row.weakness}` : label;
      return { label, value, detail: `${name}: ${spec.format(value)}` };
    })
    .filter((point) => point.label && Number.isFinite(point.value));
  if (points.length < 2) return null;
  return spec.form === "bars" ? (
    <Bars points={points} format={spec.format} />
  ) : (
    <Columns points={points} format={spec.format} />
  );
}

const ROW = 26;
const BAR = 16;
const LABEL = 132;
const VALUE = 64;

function Bars({ points, format }: { points: Point[]; format: (value: number) => string }) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const height = points.length * ROW;
  const max = Math.max(...points.map((point) => point.value), 1);
  const span = Math.max(0, width - LABEL - VALUE);

  return (
    <div ref={box} className={`relative mt-3 w-full ${COLOR}`} style={{ height }}>
      {width > 0 && (
        <svg
          width={width}
          height={height}
          className="block"
          role="img"
          aria-label="Bar chart of the results"
        >
          {points.map((point, index) => {
            const barWidth = Math.max(2, (point.value / max) * span);
            const y = index * ROW;
            return (
              <g key={`${point.label}-${index}`} {...markProps(point.detail, point.detail)}>
                <rect x={0} y={y} width={width} height={ROW} fill="transparent" />
                <text x={0} y={y + 17} className="fill-muted-foreground text-xs">
                  {short(point.label)}
                </text>
                <path
                  d={barPath(LABEL, y + (ROW - BAR) / 2, barWidth, BAR)}
                  className="fill-(--ai-bar)"
                />
                <text
                  x={LABEL + barWidth + 6}
                  y={y + 17}
                  className="fill-foreground text-xs tabular-nums"
                >
                  {format(point.value)}
                </text>
              </g>
            );
          })}
        </svg>
      )}
      {tooltip}
    </div>
  );
}

const PLOT = 140;
const AXIS = 20;

function Columns({ points, format }: { points: Point[]; format: (value: number) => string }) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const max = Math.max(...points.map((point) => point.value), 1);
  const slot = width / points.length;
  const columnWidth = Math.max(1, Math.min(24, slot - 2));
  // Label every nth column, counting back from the latest, so years never collide.
  const every = Math.max(1, Math.ceil(36 / Math.max(slot, 1)));
  const last = points[points.length - 1]!;

  return (
    <div ref={box} className={`relative mt-3 w-full ${COLOR}`} style={{ height: PLOT + AXIS }}>
      {width > 0 && (
        <svg
          width={width}
          height={PLOT + AXIS}
          className="block"
          role="img"
          aria-label="Column chart of the results"
        >
          <line x1={0} x2={width} y1={PLOT} y2={PLOT} className="stroke-border" />
          {points.map((point, index) => {
            const h = Math.max(1, (point.value / max) * (PLOT - 16));
            const x = index * slot + (slot - columnWidth) / 2;
            const showLabel = (points.length - 1 - index) % every === 0;
            return (
              <g key={`${point.label}-${index}`} {...markProps(point.detail, point.detail)}>
                <rect x={index * slot} y={0} width={slot} height={PLOT + AXIS} fill="transparent" />
                <path d={columnPath(x, PLOT - h, columnWidth, h)} className="fill-(--ai-bar)" />
                {showLabel && (
                  <text
                    x={x + columnWidth / 2}
                    y={PLOT + 14}
                    textAnchor="middle"
                    className="fill-muted-foreground text-[10px] tabular-nums"
                  >
                    {point.label}
                  </text>
                )}
              </g>
            );
          })}
          <text
            x={width}
            y={10}
            textAnchor="end"
            className="fill-muted-foreground text-xs tabular-nums"
          >
            {`${last.label}: ${format(last.value)}`}
          </text>
        </svg>
      )}
      {tooltip}
    </div>
  );
}
