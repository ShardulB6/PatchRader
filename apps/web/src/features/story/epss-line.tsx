import { type ReactNode, useRef, useState } from "react";

import { DataTable, percent, useChartTooltip, useElementWidth, useInView } from "./chart-kit";

type Point = { offset: number; median: number; n: number };

const HEIGHT = 200;
const LEFT = 36;
const RIGHT = 44;
const TOP = 12;
const BOTTOM = 26;

function describe(offset: number) {
  if (offset === 0) return "Month of listing";
  const months = Math.abs(offset) === 1 ? "month" : "months";
  return offset < 0 ? `${-offset} ${months} before listing` : `${offset} ${months} after listing`;
}

/** Median EPSS by month relative to the KEV listing month. */
export function EpssLine({ points, caption }: { points: Point[]; caption?: ReactNode }) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const inView = useInView(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const [active, setActive] = useState<number | null>(null);

  const first = points[0]!.offset;
  const last = points.at(-1)!.offset;
  const top = Math.ceil(Math.max(...points.map((point) => point.median)) * 4) / 4;
  const base = HEIGHT - BOTTOM;
  const x = (offset: number) => LEFT + ((offset - first) / (last - first)) * (width - LEFT - RIGHT);
  const y = (value: number) => base - (value / top) * (base - TOP);
  const line = points.map((point) => `${x(point.offset)},${y(point.median)}`).join(" ");
  const half = (x(first + 1) - x(first)) / 2;
  const labelled = new Map([
    [-1, { anchor: "end", dx: -4, dy: -10 }],
    [0, { anchor: "start", dx: 8, dy: 4 }],
    [last, { anchor: "start", dx: 8, dy: 4 }],
  ] as const);

  return (
    <>
      <div ref={box} className="relative w-full" style={{ height: HEIGHT }}>
        {width > 0 && (
          <svg width={width} height={HEIGHT} className="block">
            {[0, top / 2, top].map((tick) => (
              <g key={tick}>
                <line
                  x1={LEFT}
                  x2={width - RIGHT}
                  y1={y(tick)}
                  y2={y(tick)}
                  className={tick ? "stroke-border" : "stroke-muted-foreground/50"}
                />
                <text
                  x={LEFT - 6}
                  y={y(tick) + 4}
                  textAnchor="end"
                  className="fill-muted-foreground text-[11px] tabular-nums"
                >
                  {percent(tick)}
                </text>
              </g>
            ))}
            <line x1={x(0)} x2={x(0)} y1={TOP} y2={base} className="stroke-muted-foreground/60" />
            <text
              x={x(0) - 6}
              y={TOP + 10}
              textAnchor="end"
              className="fill-muted-foreground text-[11px]"
            >
              Month of listing
            </text>
            <polygon
              points={`${line} ${x(last)},${base} ${x(first)},${base}`}
              className="fill-(--story-s1)/10 transition-opacity delay-700 duration-700 motion-reduce:transition-none"
              style={{ opacity: inView ? 1 : 0 }}
            />
            <polyline
              points={line}
              pathLength={1}
              fill="none"
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
              strokeDasharray={1}
              className="stroke-(--story-s1) transition-[stroke-dashoffset] duration-[1600ms] ease-in-out motion-reduce:transition-none"
              style={{ strokeDashoffset: inView ? 0 : 1 }}
            />
            {points.map((point) => {
              const label = labelled.get(point.offset);
              const detail = `${describe(point.offset)}: median EPSS ${percent(point.median, 1)} (${point.n} vulnerabilities)`;
              const props = markProps(detail, detail);
              return (
                <g
                  key={point.offset}
                  {...props}
                  onPointerEnter={() => setActive(point.offset)}
                  onPointerLeave={() => {
                    setActive(null);
                    props.onPointerLeave();
                  }}
                  onFocus={(event) => {
                    setActive(point.offset);
                    props.onFocus(event);
                  }}
                  onBlur={() => {
                    setActive(null);
                    props.onBlur();
                  }}
                >
                  <rect
                    x={x(point.offset) - half}
                    y={TOP}
                    width={half * 2}
                    height={base - TOP + BOTTOM}
                    fill="transparent"
                  />
                  <text
                    x={x(point.offset)}
                    y={HEIGHT - 8}
                    textAnchor="middle"
                    className="fill-muted-foreground text-[11px] tabular-nums"
                  >
                    {point.offset > 0
                      ? `+${point.offset}`
                      : point.offset === 0
                        ? "0"
                        : `−${-point.offset}`}
                  </text>
                  {(label || active === point.offset) && (
                    <circle
                      cx={x(point.offset)}
                      cy={y(point.median)}
                      r={4}
                      strokeWidth={2}
                      className="fill-(--story-s1) stroke-background transition-opacity delay-1000 duration-300 motion-reduce:transition-none"
                      style={{ opacity: inView ? 1 : 0 }}
                    />
                  )}
                  {label && (
                    <text
                      x={x(point.offset) + label.dx}
                      y={y(point.median) + label.dy}
                      textAnchor={label.anchor}
                      className="fill-foreground text-xs font-semibold tabular-nums transition-opacity delay-1000 duration-300 motion-reduce:transition-none"
                      style={{ opacity: inView ? 1 : 0 }}
                    >
                      {percent(point.median, point.median < 0.1 ? 1 : 0)}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        )}
        {tooltip}
      </div>
      {caption}
      <DataTable
        head={["Months from listing", "Median EPSS", "Vulnerabilities with a score"]}
        rows={points.map((point) => [
          point.offset > 0 ? `+${point.offset}` : point.offset,
          percent(point.median, 1),
          point.n,
        ])}
      />
    </>
  );
}
