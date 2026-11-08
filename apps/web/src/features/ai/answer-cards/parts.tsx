import type { ReactNode } from "react";

// The story page's series blue, light and dark, as used by the answer charts.
export const BLUE = "[--ai-blue:#2a78d6] dark:[--ai-blue:#3987e5]";

export function Tag({
  children,
  tone = "muted",
}: {
  children: ReactNode;
  tone?: "muted" | "danger";
}) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] leading-4 ${
        tone === "danger" ? "bg-destructive/10 text-destructive" : "bg-muted text-muted-foreground"
      }`}
    >
      {children}
    </span>
  );
}

export function ExploitTags({ sources }: { sources: string[] }) {
  if (sources.length === 0)
    return <span className="text-xs text-muted-foreground">None found</span>;
  return (
    <span className="flex flex-wrap gap-1.5">
      {sources.map((source) => (
        <Tag key={source} tone="danger">
          {source}
        </Tag>
      ))}
    </span>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className="text-xs">{children}</div>
    </div>
  );
}
