import { Button } from "@PatchRader/ui/components/button";
import { Card, CardContent } from "@PatchRader/ui/components/card";
import { cn } from "@PatchRader/ui/lib/utils";
import {
  type KeyboardEvent,
  type MouseEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  type DiagramEdge,
  type DiagramItem,
  EDGES,
  FLOW_NAMES,
  type Flow,
  GROUPS,
  NODES,
} from "./architecture-data";

type Filter = Flow | "all";

const FILTERS: readonly { value: Filter; label: string }[] = [
  { value: "all", label: "Everything" },
  { value: "story", label: FLOW_NAMES.story },
  { value: "ai", label: FLOW_NAMES.ai },
  { value: "impact", label: FLOW_NAMES.impact },
];

const CAPTIONS: Record<Filter, string> = {
  all: "Click any box for details, or pick a path above to trace it through the system.",
  story:
    "The story page never calls the API. Its charts are a JSON file built offline and bundled into the app.",
  ai: "FastAPI asks watsonx.ai to pick one fixed query, runs it in DuckDB, then has watsonx.ai summarize the rows. Without watsonx.ai, a keyword router picks the query and the answer comes straight from the rows.",
  impact:
    "This is the only place the ML ranking reaches the site. impact.py reads outputs/top500.csv and looks up each CVE through DuckDB.",
};

const FADE = "transition-opacity motion-reduce:transition-none";

function arrowhead(points: DiagramEdge["points"]) {
  const [fromX, fromY] = points[points.length - 2]!;
  const [x, y] = points[points.length - 1]!;
  const dx = Math.sign(x - fromX);
  const dy = Math.sign(y - fromY);
  const back = 7;
  const side = 4;
  return `${x},${y} ${x - dx * back - dy * side},${y - dy * back - dx * side} ${x - dx * back + dy * side},${y - dy * back + dx * side}`;
}

function Edge({ edge, on, dim }: { edge: DiagramEdge; on: boolean; dim: boolean }) {
  const d = edge.points.map(([x, y], i) => `${i ? "L" : "M"}${x} ${y}`).join("");
  return (
    <g
      className={cn(
        "pointer-events-none",
        FADE,
        on ? "text-primary" : "text-muted-foreground",
        dim && "opacity-20",
      )}
    >
      <path
        d={d}
        fill="none"
        stroke="currentColor"
        strokeWidth={on ? 2 : 1.25}
        strokeDasharray={edge.unused ? "4 3" : undefined}
      />
      <polygon points={arrowhead(edge.points)} fill="currentColor" />
    </g>
  );
}

type Select = (id: string, element: SVGGElement) => void;

function hotspot(item: DiagramItem, select: Select, on: boolean, dim: boolean) {
  return {
    role: "button",
    tabIndex: 0,
    "aria-label": `${item.title}: ${item.subtitle}`,
    className: cn("group cursor-pointer outline-none", FADE, dim && "opacity-20"),
    onClick: (event: MouseEvent<SVGGElement>) => select(item.id, event.currentTarget),
    onKeyDown: (event: KeyboardEvent<SVGGElement>) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        select(item.id, event.currentTarget);
      }
    },
    "data-on": on || undefined,
  } as const;
}

const OUTLINE =
  "group-hover:stroke-primary group-focus-visible:stroke-primary group-focus-visible:[stroke-width:2.5px]";

function Node({
  item,
  select,
  on,
  dim,
  selected,
}: {
  item: DiagramItem;
  select: Select;
  on: boolean;
  dim: boolean;
  selected: boolean;
}) {
  const lines = [item.subtitle, item.subtitle2].filter(Boolean);
  const firstLine = item.y + item.h / 2 - lines.length * 7.5 + 4;
  return (
    <g {...hotspot(item, select, on, dim)}>
      <rect
        x={item.x}
        y={item.y}
        width={item.w}
        height={item.h}
        strokeWidth={selected ? 2.5 : on ? 1.5 : 1}
        strokeDasharray={item.kind === "unused" ? "4 3" : undefined}
        className={cn(
          OUTLINE,
          item.kind === "file" && "fill-primary/15 stroke-primary/40",
          item.kind === "unused" && "fill-background stroke-muted-foreground",
          !item.kind && "fill-card stroke-foreground/25",
          (on || selected) && "stroke-primary",
        )}
      />
      <text
        x={item.x + 12}
        y={firstLine}
        className={cn("fill-foreground text-[12.5px] font-semibold", item.mono && "font-mono")}
      >
        {item.title}
      </text>
      {lines.map((line, i) => (
        <text
          key={line}
          x={item.x + 12}
          y={firstLine + (i + 1) * 15}
          className="fill-muted-foreground text-[11px]"
        >
          {line}
        </text>
      ))}
    </g>
  );
}

export function ArchitectureDiagram() {
  const [filter, setFilter] = useState<Filter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const lastHotspot = useRef<SVGGElement | null>(null);

  const selectItem: Select = (id, element) => {
    lastHotspot.current = element;
    setSelectedId(id);
  };

  // Closing hides the panel, so focus goes back to the box that opened it.
  const closeDetails = useCallback(() => {
    setSelectedId(null);
    lastHotspot.current?.focus();
    lastHotspot.current = null;
  }, []);

  useEffect(() => {
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") closeDetails();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [closeDetails]);

  const isOn = (flows: readonly Flow[]) => filter !== "all" && flows.includes(filter);
  const isDim = (flows: readonly Flow[]) => filter !== "all" && !flows.includes(filter);
  const selected = [...GROUPS, ...NODES].find((item) => item.id === selectedId);

  return (
    <section aria-label="Interactive architecture diagram">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Trace a path">
        {FILTERS.map(({ value, label }) => (
          <Button
            key={value}
            variant={filter === value ? "default" : "outline"}
            aria-pressed={filter === value}
            onClick={() => setFilter(value)}
          >
            {label}
          </Button>
        ))}
      </div>
      <p className="mt-2 mb-3 min-h-10 max-w-3xl text-sm text-muted-foreground" aria-live="polite">
        {CAPTIONS[filter]}
      </p>

      <div className="grid items-start gap-7 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div className="min-w-0">
          <div className="overflow-x-auto">
            <svg
              viewBox="0 0 728 812"
              role="group"
              aria-label="PatchRader architecture. Each component can be selected for details."
              className="block h-auto w-full min-w-[660px]"
            >
              <text
                x={0}
                y={12}
                className="fill-muted-foreground text-[11px] font-semibold tracking-wide"
              >
                OFFLINE: RUN BY HAND
              </text>
              <rect
                x={0.5}
                y={414}
                width={727}
                height={314}
                fill="none"
                strokeDasharray="6 4"
                className="stroke-foreground/25"
              />
              <text
                x={12}
                y={700}
                className="fill-muted-foreground text-[11px] font-semibold tracking-wide"
              >
                LIVE ON VULTR
              </text>
              <text x={12} y={716} className="fill-muted-foreground text-[11px]">
                patchrader.health
              </text>

              {GROUPS.map((group) => {
                const on = isOn(group.flows);
                const active = group.id === selectedId;
                return (
                  <g key={group.id} {...hotspot(group, selectItem, on, isDim(group.flows))}>
                    <rect
                      x={group.x}
                      y={group.y}
                      width={group.w}
                      height={group.h}
                      fill="none"
                      pointerEvents="all"
                      strokeWidth={active ? 2.5 : on ? 1.5 : 1}
                      className={cn(
                        OUTLINE,
                        on || active ? "stroke-primary" : "stroke-foreground/25",
                      )}
                    />
                    <text
                      x={group.labelX}
                      y={group.labelY}
                      textAnchor={group.subtitleY ? "start" : "middle"}
                      className="fill-foreground text-[13px] font-semibold"
                    >
                      {group.title}
                      {!group.subtitleY && (
                        <tspan dx={8} className="fill-muted-foreground text-[11px] font-normal">
                          {group.subtitle}
                        </tspan>
                      )}
                    </text>
                    {group.subtitleY && (
                      <text
                        x={group.labelX}
                        y={group.subtitleY}
                        className="fill-muted-foreground text-[11px]"
                      >
                        {group.subtitle}
                      </text>
                    )}
                  </g>
                );
              })}

              {EDGES.map((edge) => (
                <Edge
                  key={edge.points.join()}
                  edge={edge}
                  on={isOn(edge.flows)}
                  dim={isDim(edge.flows)}
                />
              ))}

              {NODES.map((node) => (
                <Node
                  key={node.id}
                  item={node}
                  select={selectItem}
                  on={isOn(node.flows)}
                  dim={isDim(node.flows)}
                  selected={node.id === selectedId}
                />
              ))}

              {EDGES.flatMap((edge) =>
                edge.label ? (
                  <text
                    key={edge.label.text}
                    x={edge.label.x}
                    y={edge.label.y}
                    textAnchor={edge.label.end ? "end" : "start"}
                    className={cn(
                      "pointer-events-none fill-muted-foreground stroke-background text-[11px] [paint-order:stroke] [stroke-linejoin:round] [stroke-width:4px]",
                      FADE,
                      isDim(edge.flows) && "opacity-20",
                    )}
                  >
                    {edge.label.text}
                  </text>
                ) : (
                  []
                ),
              )}
            </svg>
          </div>
          <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <i className="inline-block h-3 w-4 border border-primary/40 bg-primary/15" />
              Committed to git
            </span>
            <span className="inline-flex items-center gap-1.5">
              <i className="inline-block h-3 w-4 border border-dashed border-muted-foreground" />
              Not used by the live site
            </span>
          </div>
        </div>

        <Card
          aria-live="polite"
          className={cn(
            "fixed inset-x-2 bottom-2 z-10 max-h-[45vh] overflow-y-auto shadow-lg lg:sticky lg:inset-x-auto lg:top-0 lg:bottom-auto lg:max-h-none lg:shadow-none",
            !selected && "hidden lg:flex",
          )}
        >
          <CardContent className="relative space-y-2.5 text-sm leading-relaxed">
            {selected ? (
              <>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="Close details"
                  className="absolute top-0 right-2 lg:hidden"
                  onClick={closeDetails}
                >
                  ×
                </Button>
                <h3 className="pr-6 text-base font-semibold break-words">{selected.title}</h3>
                {selected.path && (
                  <code className="block text-xs break-words text-muted-foreground">
                    {selected.path}
                  </code>
                )}
                {selected.details.map((detail) => (
                  <p key={detail}>{detail}</p>
                ))}
                <p className="text-xs text-muted-foreground">
                  {selected.flows.length
                    ? `Used by: ${selected.flows.map((flow) => FLOW_NAMES[flow]).join(", ")}`
                    : "Not used by the live site"}
                </p>
              </>
            ) : (
              <p className="text-muted-foreground">
                Click any box in the diagram to see what it does and where it lives.
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
