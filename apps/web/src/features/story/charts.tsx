import { type PointerEvent, type ReactNode, useMemo, useRef, useState } from "react";

import { DataTable, count, useChartTooltip, useElementWidth } from "./chart-kit";
import data from "./model-data.json";

/** Exact (Clopper-Pearson) 95% interval for x successes in n trials. */
function logGamma(x: number) {
  const c = [
    76.180091729471, -86.50532032941677, 24.01409824083091, -1.231739572450155,
    0.1208650973866179e-2, -0.5395239384953e-5,
  ];
  let y = x;
  let t = x + 5.5;
  t -= (x + 0.5) * Math.log(t);
  let s = 1.000000000190015;
  for (const ci of c) s += ci / ++y;
  return -t + Math.log((2.506628274631 * s) / x);
}
function betaCf(a: number, b: number, x: number) {
  const tiny = 1e-30;
  const qab = a + b;
  const qap = a + 1;
  const qam = a - 1;
  let c = 1;
  let d = 1 - (qab * x) / qap;
  d = 1 / (Math.abs(d) < tiny ? tiny : d);
  let h = d;
  for (let m = 1; m <= 200; m++) {
    const m2 = 2 * m;
    let aa = (m * (b - m) * x) / ((qam + m2) * (a + m2));
    d = 1 + aa * d;
    d = 1 / (Math.abs(d) < tiny ? tiny : d);
    c = 1 + aa / c;
    if (Math.abs(c) < tiny) c = tiny;
    h *= d * c;
    aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2));
    d = 1 + aa * d;
    d = 1 / (Math.abs(d) < tiny ? tiny : d);
    c = 1 + aa / c;
    if (Math.abs(c) < tiny) c = tiny;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < 3e-12) break;
  }
  return h;
}
function incBeta(x: number, a: number, b: number) {
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  const bt = Math.exp(
    a * Math.log(x) + b * Math.log(1 - x) - (logGamma(a) + logGamma(b) - logGamma(a + b)),
  );
  return x < (a + 1) / (a + b + 2)
    ? (bt * betaCf(a, b, x)) / a
    : 1 - (bt * betaCf(b, a, 1 - x)) / b;
}
function betaQuantile(p: number, a: number, b: number) {
  let lo = 0;
  let hi = 1;
  for (let i = 0; i < 80; i++) {
    const mid = (lo + hi) / 2;
    if (incBeta(mid, a, b) < p) lo = mid;
    else hi = mid;
  }
  return (lo + hi) / 2;
}
export function exactInterval(x: number, n: number): [number, number] {
  return [
    x === 0 ? 0 : betaQuantile(0.025, x, n - x + 1),
    x === n ? 1 : betaQuantile(0.975, x + 1, n - x),
  ];
}

/** Rounded data end, square at the baseline. */
function barPath(x: number, y: number, width: number, height: number, r = 4) {
  if (width < r) return `M${x} ${y}h${width}v${height}h${-width}z`;
  return `M${x} ${y}h${width - r}q${r} 0 ${r} ${r}v${height - 2 * r}q0 ${r} ${-r} ${r}h${-(width - r)}z`;
}
/** The same bar growing leftward from xEnd. */
function barPathLeft(xEnd: number, y: number, width: number, height: number, r = 4) {
  const x = xEnd - width;
  if (width < r) return `M${x} ${y}h${width}v${height}h${-width}z`;
  return `M${xEnd} ${y}h${-(width - r)}q${-r} 0 ${-r} ${r}v${height - 2 * r}q0 ${r} ${r} ${r}h${width - r}z`;
}

const Tip = ({ title, rows }: { title: string; rows: [string, string][] }) => (
  <div className="grid gap-0.5">
    <span className="font-semibold">{title}</span>
    {rows.map(([k, v]) => (
      <span key={k} className="flex justify-between gap-3">
        <span className="text-muted-foreground">{k}</span>
        <span className="tabular-nums">{v}</span>
      </span>
    ))}
  </div>
);

// ---- Generic horizontal bars --------------------------------------------------------------------

export type BarRow = {
  label: string;
  value: number;
  text: string;
  ci?: [number, number];
  tip: [string, string][];
};

export function HBars({
  rows,
  label = "Bars",
  labelWidth = 150,
  max,
  axis,
  table,
}: {
  rows: BarRow[];
  label?: string;
  labelWidth?: number;
  max?: number;
  axis?: number[];
  table: { head: string[]; rows: (string | number)[][] };
}) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const ROW = 28;
  const valueWidth = 64;
  const top = max ?? Math.max(...rows.map((r) => r.value));
  const height = rows.length * ROW + (axis ? 22 : 0);
  const span = Math.max(0, width - labelWidth - valueWidth);
  const x = (v: number) => labelWidth + (Math.min(v, top) / top) * span;

  return (
    <>
      <div ref={box} className="relative w-full" style={{ height }}>
        {width > 0 && (
          <svg width={width} height={height} className="block" role="img" aria-label={label}>
            {axis?.map((t) => (
              <g key={t}>
                <line x1={x(t)} x2={x(t)} y1={0} y2={rows.length * ROW} className="stroke-border" />
                <text
                  x={x(t)}
                  y={height - 4}
                  textAnchor="middle"
                  className="fill-muted-foreground text-[11px]"
                >
                  {t}
                </text>
              </g>
            ))}
            {rows.map((row, i) => {
              const y = i * ROW;
              return (
                <g
                  key={row.label}
                  {...markProps(row.label, <Tip title={row.label} rows={row.tip} />)}
                >
                  <rect x={0} y={y} width={width} height={ROW} fill="transparent" />
                  <text
                    x={0}
                    y={y + 18}
                    className={`text-xs ${i === 0 ? "fill-foreground font-semibold" : "fill-muted-foreground"}`}
                  >
                    {row.label}
                  </text>
                  <path
                    d={barPath(labelWidth, y + 6, Math.max(2, x(row.value) - labelWidth), 16)}
                    className="fill-(--story-s1)"
                  />
                  {row.ci && (
                    <g className="stroke-foreground" strokeWidth={1.2}>
                      <line x1={x(row.ci[0])} x2={x(row.ci[1])} y1={y + 14} y2={y + 14} />
                      <line x1={x(row.ci[0])} x2={x(row.ci[0])} y1={y + 9} y2={y + 19} />
                      <line x1={x(row.ci[1])} x2={x(row.ci[1])} y1={y + 9} y2={y + 19} />
                    </g>
                  )}
                  <text
                    x={width}
                    y={y + 18}
                    textAnchor="end"
                    className="fill-muted-foreground text-xs tabular-nums"
                  >
                    {row.text}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
        {tooltip}
      </div>
      <DataTable head={table.head} rows={table.rows} />
    </>
  );
}

// ---- Catch curve: exploited CVEs caught vs. CVEs reviewed ---------------------------------------

const SERIES = [
  {
    key: "model",
    name: "Our model",
    className: "stroke-(--story-s1)",
    width: 2.5,
    dash: undefined,
  },
  {
    key: "exploit_epss",
    name: "Exploit code, then EPSS",
    className: "stroke-(--story-s2)",
    width: 2,
    dash: undefined,
  },
  {
    key: "epss",
    name: "EPSS alone",
    className: "stroke-muted-foreground",
    width: 1.5,
    dash: "6 4",
  },
  {
    key: "cvss",
    name: "CVSS score",
    className: "stroke-muted-foreground",
    width: 1.5,
    dash: "2 4",
  },
] as const;

export function CatchCurveLegend() {
  return (
    <div className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {SERIES.map((s) => (
        <span key={s.key} className="flex items-center gap-1.5">
          <svg width={18} height={4} aria-hidden="true">
            <line
              x1={0}
              x2={18}
              y1={2}
              y2={2}
              className={s.className}
              strokeWidth={2}
              strokeDasharray={s.dash}
            />
          </svg>
          {s.name}
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="inline-block size-2.5 rounded-full bg-(--story-s3)" />
        Patch every CVSS 9+
      </span>
    </div>
  );
}

export function CatchCurve() {
  const C = data.curve;
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, showAt, hide } = useChartTooltip(box);
  const [hover, setHover] = useState<number | null>(null);
  const narrow = width < 560;
  const height = narrow ? 280 : 340;
  const m = { l: 34, r: narrow ? 72 : 150, t: 10, b: 36 };
  const P = C.positives;
  const x0 = 1;
  const x1 = Math.log10(C.n);
  const X = (v: number) => m.l + ((Math.log10(v) - x0) / (x1 - x0)) * (width - m.l - m.r);
  const Y = (v: number) => height - m.b - (v / P) * (height - m.t - m.b);
  const path = (vals: number[]) =>
    C.ks.map((k, i) => `${i ? "L" : "M"}${X(k).toFixed(1)} ${Y(vals[i]!).toFixed(1)}`).join("");
  const caught = C.series.model[C.ks.indexOf(C.k)]!;

  const ends = SERIES.map((s) => ({ s, y: Y(C.series[s.key][C.ks.length - 1]!) })).sort(
    (a, b) => a.y - b.y,
  );
  let last = -1e9;
  const labelled = ends.map((e) => {
    const ly = Math.max(e.y, last + 14);
    last = ly;
    return { ...e, ly };
  });

  const onMove = (event: PointerEvent<SVGRectElement>) => {
    const r = event.currentTarget.ownerSVGElement!.getBoundingClientRect();
    const sx = event.clientX - r.left;
    let best = 0;
    let dist = Infinity;
    C.ks.forEach((k, i) => {
      const d = Math.abs(X(k) - sx);
      if (d < dist) {
        dist = d;
        best = i;
      }
    });
    setHover(best);
    const k = C.ks[best]!;
    showAt(
      r.left + X(k),
      event.clientY,
      <Tip
        title={`Top ${count(k)} reviewed`}
        rows={[
          ...SERIES.map((s) => [s.name, `${C.series[s.key][best]} of ${P}`] as [string, string]),
          ["Random order", ((P * k) / C.n).toFixed(1)],
        ]}
      />,
    );
  };

  return (
    <>
      <div ref={box} className="relative w-full" style={{ height }}>
        {width > 0 && (
          <svg
            width={width}
            height={height}
            className="block"
            role="img"
            aria-label="Exploited CVEs caught versus CVEs reviewed"
          >
            {[0, 10, 20, 30, 40, 50].map((v) => (
              <g key={v}>
                <line x1={m.l} x2={width - m.r} y1={Y(v)} y2={Y(v)} className="stroke-border" />
                <text
                  x={m.l - 8}
                  y={Y(v) + 4}
                  textAnchor="end"
                  className="fill-muted-foreground text-[11px]"
                >
                  {v}
                </text>
              </g>
            ))}
            {[10, 100, 1000, 10000].map((v) => (
              <text
                key={v}
                x={X(v)}
                y={height - m.b + 16}
                textAnchor="middle"
                className="fill-muted-foreground text-[11px]"
              >
                {count(v)}
              </text>
            ))}
            <text x={m.l} y={height - 2} className="fill-muted-foreground text-[11px]">
              CVEs reviewed, log scale
            </text>
            <path
              d={path(C.ks.map((k) => (P * k) / C.n))}
              fill="none"
              className="stroke-border"
              strokeWidth={1.5}
              strokeDasharray="1 4"
            />
            <line
              x1={X(C.k)}
              x2={X(C.k)}
              y1={m.t}
              y2={height - m.b}
              className="stroke-muted-foreground"
              strokeDasharray="4 4"
            />
            <text
              x={X(C.k) + 6}
              y={m.t + 12}
              className="fill-muted-foreground stroke-background text-[11px] [paint-order:stroke]"
              strokeWidth={4}
            >
              top {C.k}
            </text>
            {[...SERIES].reverse().map((s) => (
              <path
                key={s.key}
                d={path(C.series[s.key])}
                fill="none"
                className={s.className}
                strokeWidth={s.width}
                strokeDasharray={s.dash}
                strokeLinejoin="round"
              />
            ))}
            {labelled.map((e) => (
              <text
                key={e.s.key}
                x={width - m.r + 8}
                y={e.ly + 4}
                className={`text-[11px] ${e.s.key === "model" ? "fill-foreground font-semibold" : "fill-muted-foreground"}`}
              >
                {narrow ? e.s.name.split(",")[0] : e.s.name}
              </text>
            ))}
            <circle
              cx={X(C.cvss9.flagged)}
              cy={Y(C.cvss9.caught)}
              r={6}
              className="fill-(--story-s3) stroke-background"
              strokeWidth={2}
            />
            <text
              x={X(C.cvss9.flagged)}
              y={Y(C.cvss9.caught) + 22}
              textAnchor="middle"
              className="fill-muted-foreground stroke-background text-[11px] [paint-order:stroke]"
              strokeWidth={4}
            >
              CVSS 9+: {C.cvss9.caught} caught in {count(C.cvss9.flagged)}
            </text>
            <circle
              cx={X(C.k)}
              cy={Y(caught)}
              r={5}
              className="fill-(--story-s1) stroke-background"
              strokeWidth={2}
            />
            <text
              x={X(C.k) - 8}
              y={Y(caught) - 10}
              textAnchor="end"
              className="fill-foreground stroke-background text-xs font-semibold [paint-order:stroke]"
              strokeWidth={4}
            >
              {caught} caught
            </text>
            {hover !== null && (
              <line
                x1={X(C.ks[hover]!)}
                x2={X(C.ks[hover]!)}
                y1={m.t}
                y2={height - m.b}
                className="stroke-muted-foreground"
                opacity={0.5}
              />
            )}
            <rect
              x={m.l}
              y={m.t}
              width={Math.max(0, width - m.l - m.r)}
              height={height - m.t - m.b}
              fill="transparent"
              onPointerMove={onMove}
              onPointerLeave={() => {
                setHover(null);
                hide();
              }}
            />
          </svg>
        )}
        {tooltip}
      </div>
      <DataTable
        head={["CVEs reviewed", ...SERIES.map((s) => s.name)]}
        rows={[100, 243, 597, 1000, 4682].map((k) => {
          const i = C.ks.reduce(
            (best, v, j) => (Math.abs(v - k) < Math.abs(C.ks[best]! - k) ? j : best),
            0,
          );
          return [count(C.ks[i]!), ...SERIES.map((s) => C.series[s.key][i]!)];
        })}
      />
    </>
  );
}

// ---- Issuer gate: grouped bars by year ----------------------------------------------------------

const GROUPS = [
  {
    key: "large",
    share: "largeShare",
    name: "Large issuer, no KEV history",
    className: "fill-(--story-s1)",
    swatch: "bg-(--story-s1)",
  },
  {
    key: "small",
    share: "smallShare",
    name: "New or small issuer, no KEV history",
    className: "fill-(--story-s3)",
    swatch: "bg-(--story-s3)",
  },
  {
    key: "rest",
    share: "restShare",
    name: "Issuers with KEV history",
    className: "fill-muted-foreground",
    swatch: "bg-muted-foreground",
  },
] as const;

export function GateLegend() {
  return (
    <div className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {GROUPS.map((g) => (
        <span key={g.key} className="flex items-center gap-1.5">
          <span className={`inline-block size-2.5 rounded-sm ${g.swatch}`} />
          {g.name}
        </span>
      ))}
    </div>
  );
}

export function GateBars() {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const BH = 12;
  const GAP = 4;
  const GG = 18;
  const L = 48;
  const V = 52;
  const max = 7;
  const per = GROUPS.length;
  const plotH = data.gate.length * per * (BH + GAP) + (data.gate.length - 1) * GG;
  const height = plotH + 22;
  const X = (v: number) => L + (Math.min(v, max) / max) * (width - L - V);
  const rows = useMemo(
    () =>
      data.gate.map((r) => ({
        year: r.year,
        groups: GROUPS.map((g) => {
          const [x, n] = r[g.key] as number[];
          const ci = exactInterval(x!, n!).map((p) => p * 1000) as [number, number];
          return { g, x: x!, n: n!, v: (1000 * x!) / n!, ci, share: r[g.share] };
        }),
      })),
    [],
  );

  let y = 0;
  return (
    <>
      <div ref={box} className="relative w-full" style={{ height }}>
        {width > 0 && (
          <svg
            width={width}
            height={height}
            className="block"
            role="img"
            aria-label="Exploited per 1,000 CVEs by issuer group and year"
          >
            {[0, 1, 2, 3, 4, 5, 6, 7].map((t) => (
              <g key={t}>
                <line x1={X(t)} x2={X(t)} y1={0} y2={plotH} className="stroke-border" />
                <text
                  x={X(t)}
                  y={height - 4}
                  textAnchor="middle"
                  className="fill-muted-foreground text-[11px]"
                >
                  {t}
                </text>
              </g>
            ))}
            {rows.map((r) => {
              const y0 = y;
              y += per * (BH + GAP) + GG;
              return (
                <g key={r.year}>
                  <text
                    x={0}
                    y={y0 + (per * (BH + GAP)) / 2 + 3}
                    className="fill-foreground text-xs font-semibold"
                  >
                    {r.year}
                  </text>
                  {r.groups.map((d, j) => {
                    const yy = y0 + j * (BH + GAP);
                    const title = `${r.year}: ${d.g.name}`;
                    return (
                      <g
                        key={d.g.key}
                        {...markProps(
                          title,
                          <Tip
                            title={title}
                            rows={[
                              ["Exploited", `${d.x} of ${count(d.n)}`],
                              ["Per 1,000", d.v.toFixed(2)],
                              ["95% interval", `${d.ci[0].toFixed(2)}–${d.ci[1].toFixed(2)}`],
                              ["Share of CVEs", d.share],
                            ]}
                          />,
                        )}
                      >
                        <rect
                          x={0}
                          y={yy - GAP / 2}
                          width={width}
                          height={BH + GAP}
                          fill="transparent"
                        />
                        <path
                          d={barPath(L, yy, Math.max(2, X(d.v) - L), BH, 3)}
                          className={d.g.className}
                        />
                        <g className="stroke-foreground" strokeWidth={1}>
                          <line x1={X(d.ci[0])} x2={X(d.ci[1])} y1={yy + BH / 2} y2={yy + BH / 2} />
                          <line x1={X(d.ci[0])} x2={X(d.ci[0])} y1={yy + 2} y2={yy + BH - 2} />
                          <line x1={X(d.ci[1])} x2={X(d.ci[1])} y1={yy + 2} y2={yy + BH - 2} />
                        </g>
                        <text
                          x={width}
                          y={yy + BH - 2}
                          textAnchor="end"
                          className="fill-muted-foreground text-[11px] tabular-nums"
                        >
                          {d.v.toFixed(2)}
                        </text>
                      </g>
                    );
                  })}
                </g>
              );
            })}
          </svg>
        )}
        {tooltip}
      </div>
      <DataTable
        head={["Year", ...GROUPS.map((g) => g.name)]}
        rows={rows.map((r) => [
          r.year,
          ...r.groups.map((d) => `${d.x} of ${count(d.n)} (${d.v.toFixed(2)})`),
        ])}
      />
    </>
  );
}

// ---- EPSS AUC by period -------------------------------------------------------------------------

export function AucDots() {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const ROW = 34;
  const L = 110;
  const V = 60;
  const height = data.epssAuc.length * ROW + 24;
  const lo = 0.3;
  const hi = 1;
  const X = (v: number) => L + ((v - lo) / (hi - lo)) * (width - L - V);
  return (
    <>
      <div ref={box} className="relative w-full" style={{ height }}>
        {width > 0 && (
          <svg
            width={width}
            height={height}
            className="block"
            role="img"
            aria-label="EPSS AUC by period"
          >
            {[0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1].map((t) => (
              <g key={t}>
                <line
                  x1={X(t)}
                  x2={X(t)}
                  y1={0}
                  y2={height - 22}
                  className={t === 0.5 ? "stroke-muted-foreground" : "stroke-border"}
                  strokeDasharray={t === 0.5 ? "3 3" : undefined}
                />
                <text
                  x={X(t)}
                  y={height - 4}
                  textAnchor="middle"
                  className="fill-muted-foreground text-[11px]"
                >
                  {t.toFixed(1)}
                </text>
              </g>
            ))}
            <text
              x={X(0.5) + 4}
              y={10}
              className="fill-muted-foreground stroke-background text-[11px] [paint-order:stroke]"
              strokeWidth={4}
            >
              random
            </text>
            {data.epssAuc.map((a, i) => {
              const y = i * ROW + 18;
              const interval =
                a.lo != null && a.hi != null
                  ? `${a.lo.toFixed(2)}–${a.hi.toFixed(2)}`
                  : "short window";
              return (
                <g
                  key={a.label}
                  {...markProps(
                    a.label,
                    <Tip
                      title={a.label}
                      rows={[
                        ["AUC", a.auc.toFixed(2)],
                        ["95% interval", interval],
                      ]}
                    />,
                  )}
                >
                  <rect x={0} y={y - ROW / 2} width={width} height={ROW} fill="transparent" />
                  <text x={0} y={y + 4} className="fill-muted-foreground text-xs">
                    {a.label}
                  </text>
                  {a.lo != null && a.hi != null && (
                    <line
                      x1={X(a.lo)}
                      x2={X(a.hi)}
                      y1={y}
                      y2={y}
                      className="stroke-(--story-s1)"
                      strokeWidth={2}
                      strokeOpacity={0.45}
                    />
                  )}
                  <circle
                    cx={X(a.auc)}
                    cy={y}
                    r={6}
                    className="fill-(--story-s1) stroke-background"
                    strokeWidth={2}
                  />
                  <text
                    x={width}
                    y={y + 4}
                    textAnchor="end"
                    className={`text-xs tabular-nums ${i === data.epssAuc.length - 1 ? "fill-foreground font-semibold" : "fill-muted-foreground"}`}
                  >
                    {a.auc.toFixed(2)}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
        {tooltip}
      </div>
      <DataTable
        head={["Period", "AUC", "95% interval"]}
        rows={data.epssAuc.map((a) => [
          a.label,
          a.auc.toFixed(2),
          a.lo != null && a.hi != null ? `${a.lo.toFixed(2)}–${a.hi.toFixed(2)}` : "—",
        ])}
      />
    </>
  );
}

// ---- Granite: one cell per submitted CVE --------------------------------------------------------

export function GraniteCells() {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { kept } = data.granite;
  const cols = width < 480 ? 25 : 50;
  const gap = 2;
  const size = width > 0 ? (width - (cols - 1) * gap) / cols : 0;
  const height = (500 / cols) * (size + gap);
  return (
    <div ref={box} className="relative w-full" style={{ height: width > 0 ? height : 120 }}>
      {width > 0 && (
        <svg
          width={width}
          height={height}
          className="block"
          role="img"
          aria-label={`${500 - kept} of our 500 picks are in the list only because of the Granite text score`}
        >
          {Array.from({ length: 500 }, (_, i) => (
            <rect
              key={i}
              x={(i % cols) * (size + gap)}
              y={Math.floor(i / cols) * (size + gap)}
              width={size}
              height={size}
              rx={Math.min(3, size / 3)}
              className={i >= kept ? "fill-(--story-s1)" : "fill-border"}
            />
          ))}
        </svg>
      )}
    </div>
  );
}

// ---- Per-CVE explanation ------------------------------------------------------------------------

export const FEATURE_LABEL: Record<string, string> = {
  log_assigner_kev_rate: "Issuer's KEV history",
  log_batch_size: "Release size",
  text_pct: "Granite text score",
  log_cwe_kev_rate: "Weakness type's KEV rate",
  cvss_filled: "CVSS score",
  ui_none: "No user interaction",
  any_exploit: "Public exploit code",
  kw_unauth: 'Says "unauthenticated"',
  product_has_kev: "Product already on KEV",
  poc_github: "Proof of concept on GitHub",
  id_age: "Old ID, filed late",
  pr_none: "No privileges needed",
  net_preauth: "Network, before login",
  cwe_path: "Path-traversal weakness",
  cwe_auth: "Authentication weakness",
  nuclei: "Nuclei scan template",
};

function Contributions({ shap }: { shap: number[] }) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, markProps } = useChartTooltip(box);
  const items = data.features
    .map((f, i) => ({ f, v: shap[i]! }))
    .filter((d) => Math.abs(d.v) >= 0.02)
    .sort((a, b) => Math.abs(b.v) - Math.abs(a.v))
    .slice(0, 9);
  const ROW = 26;
  const height = items.length * ROW;
  const L = width < 460 ? 130 : 170;
  const x0 = L + (width - L) / 2;
  const mx = Math.max(1, ...items.map((d) => Math.abs(d.v)));
  const scale = ((width - L) / 2 - 44) / mx;
  return (
    <div ref={box} className="relative w-full" style={{ height }}>
      {width > 0 && (
        <svg
          width={width}
          height={height}
          className="block"
          role="img"
          aria-label="Feature contributions"
        >
          <line x1={x0} x2={x0} y1={0} y2={height} className="stroke-border" />
          {items.map((d, i) => {
            const y = i * ROW;
            const w = Math.max(2, Math.abs(d.v) * scale);
            const pos = d.v > 0;
            const name = FEATURE_LABEL[d.f] ?? d.f;
            const value = `${pos ? "+" : "−"}${Math.abs(d.v).toFixed(2)}`;
            return (
              <g
                key={d.f}
                {...markProps(
                  name,
                  <Tip title={name} rows={[["Contribution", `${value} log-odds`]]} />,
                )}
              >
                <rect x={0} y={y} width={width} height={ROW} fill="transparent" />
                <text x={0} y={y + 17} className="fill-muted-foreground text-xs">
                  {name}
                </text>
                <path
                  d={pos ? barPath(x0, y + 6, w, 14, 3) : barPathLeft(x0, y + 6, w, 14, 3)}
                  className={pos ? "fill-(--story-s1)" : "fill-(--story-s3)"}
                />
                <text
                  x={pos ? x0 + w + 6 : x0 - w - 6}
                  y={y + 17}
                  textAnchor={pos ? "start" : "end"}
                  className="fill-muted-foreground text-[11px] tabular-nums"
                >
                  {value}
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

export function Dossier() {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(data.top[0]!.id);
  const q = query.trim().toLowerCase();
  const rows = data.top.filter(
    (r) =>
      !q ||
      r.id.toLowerCase().includes(q) ||
      r.assigner.toLowerCase().includes(q) ||
      r.desc.toLowerCase().includes(q),
  );
  const r = data.top.find((x) => x.id === selected)!;
  const chip = (text: string, on = false): ReactNode => (
    <span
      key={text}
      className={`rounded-full border px-2 py-0.5 text-xs ${on ? "border-(--story-s3) text-foreground" : "text-muted-foreground"}`}
    >
      {text}
    </span>
  );
  return (
    <div className="grid gap-5 sm:grid-cols-[15rem_minmax(0,1fr)]">
      <div className="min-w-0">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search ID, issuer or text"
          aria-label="Search the 500 submitted CVEs"
          className="w-full rounded-md border bg-background px-2.5 py-1.5 text-sm"
        />
        <div className="mt-2 max-h-90 overflow-y-auto rounded-md border">
          {rows.map((row) => (
            <button
              key={row.id}
              type="button"
              aria-pressed={row.id === selected}
              onClick={() => setSelected(row.id)}
              className="flex w-full justify-between gap-2 border-b px-2.5 py-1.5 text-left text-sm tabular-nums last:border-b-0 hover:bg-muted aria-pressed:bg-muted aria-pressed:font-semibold"
            >
              <span>{row.id}</span>
              <span className="text-muted-foreground">#{row.rank}</span>
            </button>
          ))}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">{rows.length} of 500 shown</p>
      </div>
      <div className="min-w-0">
        <p className="text-xs font-semibold text-muted-foreground">Rank {r.rank} of 500</p>
        <h3 className="text-xl font-semibold">{r.id}</h3>
        <div className="my-2 flex flex-wrap gap-1.5">
          {chip(`Issuer: ${r.assigner}`)}
          {chip(`CVSS ${r.cvss == null ? "n/a" : r.cvss.toFixed(1)}`, (r.cvss ?? 0) >= 9)}
          {chip(`EPSS ${r.epss == null ? "n/a" : (100 * r.epss).toFixed(1) + "%"}`)}
          {chip(r.exploit ? "Public exploit code" : "No public exploit code", !!r.exploit)}
        </div>
        <p className="mb-3 border-l-2 pl-2.5 text-sm text-muted-foreground">
          {r.desc}
          {r.desc.length >= 260 ? "…" : ""}
        </p>
        <Contributions shap={r.shap} />
      </div>
    </div>
  );
}

export { data };
