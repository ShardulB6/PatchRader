import { type ReactNode, useRef } from "react";

import { DataTable, percent, useChartTooltip, useElementWidth } from "./chart-kit";

type Part = { label: string; count: number; className: string };

const MIN_LABEL_WIDTH = 40;

/** One whole split into parts: what was visible before each KEV listing. */
export function VisibilityBar({
  parts,
  total,
  caption,
}: {
  parts: Part[];
  total: number;
  caption?: ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  const width = useElementWidth(box);
  const { tooltip, markProps } = useChartTooltip(box);

  return (
    <>
      <div ref={box} className="relative flex h-7 w-full gap-0.5">
        {parts.map((part) => {
          const share = part.count / total;
          const detail = `${part.label}: ${part.count} of ${total} (${percent(share)})`;
          const props = markProps(detail, detail);
          return (
            <div
              key={part.label}
              {...props}
              className={`${props.className} h-7 min-w-0 rounded px-2 text-xs leading-7 font-semibold whitespace-nowrap text-white ${part.className}`}
              style={{ flex: `${part.count} 1 0` }}
            >
              {share * width > MIN_LABEL_WIDTH ? percent(share) : null}
            </div>
          );
        })}
        {tooltip}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {parts.map((part) => (
          <span key={part.label} className="flex items-center gap-1.5">
            <i className={`inline-block size-2.5 rounded-sm ${part.className}`} />
            {part.label}
          </span>
        ))}
      </div>
      {caption}
      <DataTable
        head={["At the last month-end before listing", "Listings", "Share"]}
        rows={parts.map((part) => [part.label, part.count, percent(part.count / total)])}
      />
    </>
  );
}
