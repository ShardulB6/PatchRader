import type { ReactNode } from "react";

import { ArchitectureDiagram } from "./architecture-diagram";

const DEPLOY_STEPS: readonly ReactNode[] = [
  <>
    Merge to <code>main</code>
  </>,
  <>
    Run <code>patchrader-deploy</code> by hand
  </>,
  <>
    Clone, <code>pnpm build</code>, Python venv
  </>,
  <>
    Point <code>current</code> at the new release
  </>,
  <>
    Check <code>/story</code> and <code>/ready</code>
  </>,
];

const FOLDERS = [
  ["apps/web", "Dashboard: routes, charts, chat UI"],
  ["packages/ui", "Shared shadcn/ui components and theme"],
  ["backend", "FastAPI service behind the analyst and impact page"],
  ["ml", "Trains the ranking model, writes the top 500"],
  ["scripts", "Dataset download, feature code, story data"],
  ["notebooks", "Experiments and evidence behind the model"],
  ["outputs", "Top 500, baseline results, SHAP explanations"],
  ["deploy/vultr", "Caddy, systemd units, deploy script"],
] as const;

export function DocumentationPage() {
  return (
    <main className="mx-auto w-full max-w-7xl space-y-8 overflow-y-auto px-4 py-7 sm:px-6">
      <header>
        <h1 className="text-2xl font-semibold">How PatchRader works</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          PatchRader predicts which 500 CVEs on the 2026 scoreboard CISA will add to its Known
          Exploited Vulnerabilities list, and shows the evidence on this site.
        </p>
      </header>

      <ArchitectureDiagram />

      <section className="space-y-2.5">
        <h2 className="text-base font-semibold">Things to know</h2>
        <ul className="max-w-3xl list-disc space-y-2 pl-5 text-sm">
          <li>
            <strong>The AI Analyst doesn't use the model.</strong> When asked what to patch first,
            it sorts by public exploit signal, then EPSS. That is close to the standard ranking we
            compare the model against, so <code>/ai</code> and <code>/impact</code> can disagree.
          </li>
          <li>
            <strong>No page queries Tiger Cloud.</strong> The <code>exploit_signals</code> table is
            loaded, but the live charts come from a JSON file and the API reads CSVs.
          </li>
          <li>
            <strong>The backtest gap is within noise.</strong> The final model found 19 exploited
            CVEs on the 2025 backtest against 14 for the standard ranking. With 52 to 85 exploited
            CVEs per test, a gap under about 6 can't be told apart from luck.
          </li>
        </ul>
      </section>

      <section className="space-y-2.5">
        <h2 className="text-base font-semibold">Getting code onto the server</h2>
        <ol className="flex flex-wrap items-center gap-1.5 text-sm">
          {DEPLOY_STEPS.map((step, i) => (
            <li key={i} className="flex items-center gap-1.5">
              {i > 0 && (
                <span aria-hidden className="text-muted-foreground">
                  →
                </span>
              )}
              <span className="border px-2 py-1">{step}</span>
            </li>
          ))}
        </ol>
        <p className="max-w-3xl text-sm text-muted-foreground">
          If either check fails, the script points <code>current</code> back at the previous
          release. The three newest releases are kept.
        </p>
      </section>

      <section className="space-y-2.5">
        <h2 className="text-base font-semibold">Where things live</h2>
        <dl className="grid gap-x-6 gap-y-1.5 text-sm md:grid-cols-2">
          {FOLDERS.map(([folder, purpose]) => (
            <div key={folder} className="grid grid-cols-[6.5rem_1fr] gap-2">
              <dt className="font-mono text-xs leading-5">{folder}</dt>
              <dd className="text-muted-foreground">{purpose}</dd>
            </div>
          ))}
        </dl>
      </section>
    </main>
  );
}
