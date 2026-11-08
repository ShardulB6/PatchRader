import { Component, type ReactNode } from "react";

import type { ChatResponse, ChatRow } from "../../../lib/ai-client";
import { AnswerChart } from "../answer-chart";
import { CveCard } from "./cve-card";
import { BLUE } from "./parts";
import { QueueList } from "./queue-list";
import { list, record, text, words } from "./read";

/** An analyst answer, or just `content` for an error message. */
export type AnswerMessage = { content: string } & Partial<Omit<ChatResponse, "answer">>;

/**
 * An answer drawn as cards. If anything in the cards throws, this answer alone
 * falls back to the plain text and table, and the rest of the page keeps working.
 */
export function AnswerView({ message }: { message: AnswerMessage }) {
  return (
    <AnswerBoundary
      fallback={
        // Last resort, in case the old table or chart can't draw this data either.
        <AnswerBoundary fallback={<p className="whitespace-pre-wrap">{message.content}</p>}>
          <PlainAnswer message={message} />
        </AnswerBoundary>
      }
    >
      <RichAnswer message={message} />
    </AnswerBoundary>
  );
}

class AnswerBoundary extends Component<
  { fallback: ReactNode; children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: unknown) {
    console.error("Answer cards failed; showing the plain answer instead", error);
  }

  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

const CVE_ID = /^CVE-\d{4}-\d{4,}/i;

/** The CVE IDs the backend's "Fix first" row names (both, when both are on KEV). */
function fixFirst(rows: ChatRow[], ids: string[]): { ids: string[]; line: string | null } {
  const row = rows.find((r) => r.signal === "Fix first");
  const line = row ? (ids.map((id) => text(row[id])).find(Boolean) ?? null) : null;
  if (!line) return { ids: [], line: null };
  if (line.startsWith("Both")) return { ids, line };
  const named = line.match(CVE_ID)?.[0].toUpperCase();
  return { ids: named && ids.includes(named) ? [named] : [], line };
}

function RichAnswer({ message }: { message: AnswerMessage }) {
  const rows = Array.isArray(message.rows) ? message.rows : [];
  const cards = list(message.cves).filter((c) => text(record(c)?.cve_id));
  const ids = cards.map((c) => text(record(c)?.cve_id)!.toUpperCase());

  let body: ReactNode = null;
  let headline: string | null = null;
  if (message.operation === "compare_cves" && cards.length === 2) {
    const first = fixFirst(rows, ids);
    headline = first.line;
    body = (
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        {cards.map((card, i) => (
          <CveCard key={ids[i]} data={card} first={first.ids.includes(ids[i]!)} />
        ))}
      </div>
    );
  } else if (message.operation === "cve_rank" && cards.length === 1) {
    body = (
      <div className="mt-3">
        <CveCard data={cards[0]} />
      </div>
    );
  } else if (message.operation === "priority_queue" || message.operation === "patch_for_vendors") {
    body = <QueueList rows={rows} />;
  }

  return (
    <>
      <Summary
        message={message}
        fallbackHeadline={body ? headline : null}
        hideContent={body !== null}
      />
      {body ??
        (message.operation && rows.length > 0 && (
          <AnswerChart operation={message.operation} rows={rows} />
        ))}
      <DataTable rows={rows} open={body === null && rows.length <= 12} />
      <Footer message={message} />
    </>
  );
}

/**
 * The model's verdict and reasons. Without one, the plain answer text, unless
 * cards already show the same data, in which case only a headline (if any).
 */
function Summary({
  message,
  fallbackHeadline,
  hideContent,
}: {
  message: AnswerMessage;
  fallbackHeadline: string | null;
  hideContent: boolean;
}) {
  const summary = record(message.summary);
  // Model text must be a string; a number or object here means a bad reply.
  const headline = words(summary?.headline);
  if (!headline) {
    if (fallbackHeadline) return <Verdict headline={fallbackHeadline} />;
    if (hideContent) return null;
    return (
      <p className="whitespace-pre-wrap">
        {words(message.content) ?? "The analyst returned an empty answer. Try asking again."}
      </p>
    );
  }
  const points = list(summary?.points)
    .map(words)
    .filter((p): p is string => p !== null);
  const caveat = words(summary?.caveat);
  return (
    <div className="space-y-2">
      <Verdict headline={headline} />
      {points.length > 0 && (
        <ul className="list-disc space-y-1 pl-5">
          {points.map((point, i) => (
            <li key={i}>{point}</li>
          ))}
        </ul>
      )}
      {caveat && <p className="text-xs text-muted-foreground">{caveat}</p>}
    </div>
  );
}

export function Verdict({ headline }: { headline: string }) {
  return (
    <p
      className={`border-l-4 border-(--ai-blue) bg-muted/50 py-2 pr-2 pl-3 text-base font-semibold ${BLUE}`}
    >
      {headline}
    </p>
  );
}

export function DataTable({ rows, open }: { rows: ChatRow[]; open: boolean }) {
  if (rows.length === 0) return null;
  return (
    // Long tables start collapsed so they don't push the conversation away.
    <details open={open} className="mt-3 max-w-full overflow-x-auto">
      <summary className="cursor-pointer text-xs text-muted-foreground select-none">
        Data table ({rows.length} rows)
      </summary>
      <table className="w-full border-collapse text-left text-xs">
        <thead>
          <tr>
            {Object.keys(rows[0]!).map((key) => (
              <th key={key} className="border-b px-2 py-1">
                {key}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={rowIndex}>
              {Object.entries(row).map(([key, value]) => (
                <td key={key} className="border-b px-2 py-1">
                  {String(value ?? "")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

function Footer({ message }: { message: AnswerMessage }) {
  return (
    <>
      {message.note && <p className="mt-2 text-xs text-muted-foreground">{message.note}</p>}
      {message.mode && (
        <p className="mt-1 text-xs text-muted-foreground">
          {message.mode === "IBM watsonx.ai"
            ? "Answered by IBM watsonx.ai"
            : "Answered without AI by the keyword router (watsonx.ai not used)"}
        </p>
      )}
    </>
  );
}

/** How every answer looked before the cards; the fallback when they fail. */
function PlainAnswer({ message }: { message: AnswerMessage }) {
  const rows = Array.isArray(message.rows) ? message.rows : [];
  return (
    <>
      <p className="whitespace-pre-wrap">{message.content}</p>
      {message.operation && rows.length > 0 && (
        <AnswerChart operation={message.operation} rows={rows} />
      )}
      <DataTable rows={rows} open={rows.length <= 12} />
      <Footer message={message} />
    </>
  );
}
