// Safe readers for API data. The response is typed but never validated, so the
// cards read every field through these and treat anything unexpected as missing.

export function num(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

export function text(value: unknown): string | null {
  if (typeof value === "string") return value.trim() || null;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

/** Strings only: for text the model wrote. */
export function words(value: unknown): string | null {
  return typeof value === "string" ? value.trim() || null : null;
}

/** Description text, with the HTML spaces some CVE records contain made plain. */
export function prose(value: unknown): string | null {
  return text(typeof value === "string" ? value.replace(/&nbsp;/g, " ") : value);
}

export function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

const counter = new Intl.NumberFormat("en-US");
export const count = (value: number) => counter.format(value);

/** One decimal, rounded like the backend's text, so the cards and the answer agree. */
export const percent = (fraction: number) => `${(fraction * 100).toFixed(1)}%`;

/** One decimal, rounded down, so a 99.97th percentile doesn't read as 100.0%. */
export const percentile = (fraction: number) => `${(Math.floor(fraction * 1000) / 10).toFixed(1)}%`;

/** "palo alto networks" -> "Palo Alto Networks". */
export const vendorName = (name: string) =>
  name.replace(/\b[a-z]/g, (letter) => letter.toUpperCase());

/** Exploit-code sources in a priority-queue row, named as the backend names them. */
export const EXPLOIT_COLUMNS: [string, string][] = [
  ["exploitdb", "Exploit-DB"],
  ["metasploit", "Metasploit"],
  ["nuclei", "Nuclei"],
  ["poc_github", "GitHub PoC"],
];
