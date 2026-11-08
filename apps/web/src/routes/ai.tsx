import { createFileRoute } from "@tanstack/react-router";
import { Button } from "@PatchRader/ui/components/button";
import { useState, type FormEvent } from "react";
import { AnswerChart } from "../features/ai/answer-chart";
import { askAnalyst, type ChatRow } from "../lib/ai-client";

export const Route = createFileRoute("/ai")({ component: AnalystPage });

type Message = {
  role: "user" | "assistant";
  content: string;
  rows?: ChatRow[];
  note?: string;
  mode?: string;
  operation?: string;
};

const EXAMPLES = [
  "What should I patch first if I use Fortinet and Cisco?",
  "Why is CVE-2026-8037 ranked where it is?",
  "Should I fix CVE-2026-39808 or CVE-2026-20200 first?",
  "Which vendors have the highest KEV rate?",
  "What are the top 10 weakness types in 2025?",
  "How many vulnerabilities were published each year?",
];

function AnalystPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  function sendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void ask(input.trim());
  }

  async function ask(question: string) {
    if (!question || loading) return;
    setMessages((current) => [...current, { role: "user", content: question }]);
    setInput("");
    setLoading(true);
    try {
      const result = await askAnalyst(question);
      setMessages((current) => [
        ...current,
        {
          role: "assistant",
          content: result.answer,
          rows: result.rows,
          note: result.note,
          mode: result.mode,
          operation: result.operation,
        },
      ]);
    } catch (error) {
      setMessages((current) => [
        ...current,
        { role: "assistant", content: error instanceof Error ? error.message : "Request failed" },
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto flex h-full min-h-0 w-full max-w-5xl flex-col gap-4 p-4 sm:p-6">
      <header>
        <h1 className="text-2xl font-semibold">AI Analyst</h1>
        <p className="text-sm text-muted-foreground">Ask about CVEs, vendors, KEV, EPSS, and vulnerability trends.</p>
      </header>
      <section aria-label="Chat messages" aria-live="polite" className="min-h-0 flex-1 space-y-4 overflow-y-auto rounded-lg border p-4">
        {messages.length === 0 && (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">Try one of these:</p>
            <div className="flex flex-wrap gap-2">
              {EXAMPLES.map((example) => (
                <Button
                  key={example}
                  variant="outline"
                  size="sm"
                  className="h-auto py-1.5 text-left whitespace-normal"
                  disabled={loading}
                  onClick={() => void ask(example)}
                >
                  {example}
                </Button>
              ))}
            </div>
          </div>
        )}
        {messages.map((message, i) => (
          <article key={i} className={`max-w-full rounded-lg p-3 text-sm ${message.role === "user" ? "ml-auto w-fit bg-primary text-primary-foreground" : "border bg-card"}`}>
            <p className="whitespace-pre-wrap">{message.content}</p>
            {message.operation && message.rows && (
              <AnswerChart operation={message.operation} rows={message.rows} />
            )}
            {message.rows && message.rows.length > 0 && (
              // Long tables start collapsed so they don't push the conversation away.
              <details open={message.rows.length <= 12} className="mt-3 max-w-full overflow-x-auto">
                <summary className="cursor-pointer text-xs text-muted-foreground select-none">
                  Data table ({message.rows.length} rows)
                </summary>
                <table className="w-full border-collapse text-left text-xs">
                  <thead><tr>{Object.keys(message.rows[0]).map((key) => <th key={key} className="border-b px-2 py-1">{key}</th>)}</tr></thead>
                  <tbody>{message.rows.map((row, rowIndex) => <tr key={rowIndex}>{Object.entries(row).map(([key, value]) => <td key={key} className="border-b px-2 py-1">{String(value ?? "")}</td>)}</tr>)}</tbody>
                </table>
              </details>
            )}
            {message.note && <p className="mt-2 text-xs text-muted-foreground">{message.note}</p>}
            {message.mode && (
              <p className="mt-1 text-xs text-muted-foreground">
                {message.mode === "IBM watsonx.ai"
                  ? "Answered by IBM watsonx.ai"
                  : "Answered without AI by the keyword router (watsonx.ai not used)"}
              </p>
            )}
          </article>
        ))}
        {loading && <p role="status" className="text-sm text-muted-foreground">Analyzing…</p>}
      </section>
      <form onSubmit={sendMessage} className="flex gap-2">
        <label htmlFor="analyst-input" className="sr-only">Question</label>
        <input id="analyst-input" className="min-w-0 flex-1 rounded-md border bg-background px-3 py-2" value={input} maxLength={2000} onChange={(e) => setInput(e.target.value)} placeholder="Ask a question about vulnerability data…" />
        <button type="submit" disabled={loading || !input.trim()} className="rounded-md bg-primary px-4 py-2 text-primary-foreground disabled:opacity-50">Send</button>
      </form>
    </main>
  );
}
