export type ChatRow = Record<string, string | number | boolean | null>;
export type ChatResponse = {
  answer: string;
  mode: string;
  operation: string;
  note: string;
  rows: ChatRow[];
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

export type ImpactRow = {
  cve_id: string;
  severity: string;
  score: number | null;
  epss: number | null;
  weaknesses: string[];
  harm_categories: string[];
  exploit_ease: string;
  footprint: string;
  vendors: string[];
  contexts: string[];
  in_kev: boolean;
  ransomware_use: boolean;
  n_references: number;
  ref_domains: string[];
  description: string;
  narrative: string;
};

type Count = { label: string; count: number };

export type Top500Impact = {
  source: string;
  requested: number;
  matched: number;
  missing: string[];
  rows: ImpactRow[];
  summary: {
    headline: string;
    kev: number;
    easy: number;
    ransomware: number;
    broad: number;
    harm: Count[];
    severity: Count[];
    footprint: Count[];
    vendors: Count[];
    contexts: Count[];
    weaknesses: Count[];
  };
};

/** Returns null when top500.csv isn't in the project root. */
export async function getTop500Impact(): Promise<Top500Impact | null> {
  const response = await fetch(`${API_BASE}/api/impact/top500`);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(
      response.status === 429
        ? "Too many requests. Wait a minute and try again."
        : `Impact request failed (HTTP ${response.status}).`,
    );
  }
  return (await response.json()) as Top500Impact;
}
