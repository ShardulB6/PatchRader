export type ChatRow = Record<string, string | number | boolean | null>;
/** The model's short answer. Missing when watsonx.ai wasn't used or its reply wasn't valid. */
export type ChatSummary = { headline: string; points: string[]; caveat: string | null };
/** One CVE's ranking signals, sent with "why is it ranked here" and comparison answers. */
export type CveCardData = {
  cve_id: string;
  rank: number | null;
  ranked_total: number | null;
  epss: number | null;
  epss_pct: number | null;
  snapshot_month: string | null;
  exploit_sources: string[];
  kev_date: string | null;
  vendors: { vendor: string; cves: number; kev_cves: number }[];
  overall_kev_rate: number | null;
  cvss3_score: number | string | null;
  description: string | null;
};
export type ChatResponse = {
  answer: string;
  mode: string;
  operation: string;
  note: string;
  rows: ChatRow[];
  summary?: ChatSummary | null;
  cves?: CveCardData[];
};

// Local development only. Production should proxy /api/chat to FastAPI
// through the Vultr reverse proxy using the same public origin.
const LOCAL_API = "http://127.0.0.1:8000";
const API_BASE = import.meta.env.DEV ? LOCAL_API : "";

export async function askAnalyst(message: string): Promise<ChatResponse> {
  const response = await fetch(`${API_BASE}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  if (!response.ok) {
    // Server errors deliberately don't disclose database or credential details.
    throw new Error(
      response.status === 503
        ? "AI service is temporarily unavailable."
        : response.status === 429
          ? "Too many questions at once. Wait a minute and try again."
          : `Chat request failed (HTTP ${response.status}).`,
    );
  }
  return (await response.json()) as ChatResponse;
}
