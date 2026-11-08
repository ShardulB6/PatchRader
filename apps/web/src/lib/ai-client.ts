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
