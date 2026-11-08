import { createFileRoute } from "@tanstack/react-router";
import Top500Auto from "../features/impact-analysis/components/Top500Auto";

export const Route = createFileRoute("/impact")({ component: ImpactPage });

function ImpactPage() {
  return (
    <main className="mx-auto w-full max-w-7xl space-y-6 overflow-y-auto px-4 py-7 sm:px-6">
      <header>
        <p className="text-xs font-semibold uppercase tracking-widest text-sky-500">Vulture / Analysis</p>
        <h1 className="mt-2 text-3xl font-bold tracking-tight">Impact of the Top 500</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          Potential consequences of the CVEs in top500.csv. Place the file in the project root and the Python API
          analyzes it automatically.
        </p>
      </header>

      <Top500Auto />
    </main>
  );
}