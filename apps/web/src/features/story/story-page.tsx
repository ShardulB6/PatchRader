import type { ReactNode } from "react";

import { count, percent } from "./chart-kit";
import { EpssLine } from "./epss-line";
import { HaystackField } from "./haystack-field";
import { LagColumns } from "./lag-columns";
import { SeverityBars } from "./severity-bars";
import story from "./story-data.json";
import { VisibilityBar } from "./visibility-bar";

// Series colors for this page only, checked for color-blind separation against the
// app's light and dark backgrounds. The theme's --chart-* tokens are one blue ramp,
// which suits magnitude but cannot tell categories apart.
const SERIES =
  "[--story-s1:#2a78d6] [--story-s2:#1baf7a] [--story-s3:#eb6834] dark:[--story-s1:#3987e5] dark:[--story-s2:#199e70] dark:[--story-s3:#d95926]";

const monthName = (month: string) =>
  new Date(`${month}-01T00:00:00Z`).toLocaleDateString("en-US", {
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });

function Beat({
  step,
  kicker,
  title,
  children,
}: {
  step: number;
  kicker: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="border-b py-10 last:border-b-0">
      <p className="text-xs font-semibold text-muted-foreground">
        {step}. {kicker}
      </p>
      <h2 className="mt-1 mb-5 text-xl leading-snug font-semibold text-balance">{title}</h2>
      {children}
    </section>
  );
}

const Note = ({ children }: { children: ReactNode }) => (
  <p className="mt-3 text-xs text-muted-foreground">{children}</p>
);

export function StoryPage() {
  const { haystack, severity, weakness, lag, visibility, epss } = story;
  const critical = severity.find((row) => row.label === "Critical")!;
  const visible = visibility.total;
  const before = epss.medians.find((point) => point.offset === -1)!;
  const during = epss.medians.find((point) => point.offset === 0)!;

  // min-w-0 lets the root grid shrink this column below the charts' measured widths.
  return (
    <main className={`mx-auto w-full min-w-0 max-w-3xl px-4 pt-8 pb-16 ${SERIES}`}>
      <header className="pb-2">
        <p className="text-xs font-semibold text-muted-foreground">PatchRader</p>
        <h1 className="mt-1 text-3xl font-semibold text-balance">Before the breach</h1>
        <p className="mt-3 max-w-2xl text-sm text-muted-foreground">
          {count(haystack.published2026)} vulnerabilities were published in 2026 through November 6.
          No team can fix them all, so the question is which ones attackers will use. This page
          follows the public data on that question, using CISA's Known Exploited Vulnerabilities
          list (KEV) as the record of confirmed attacks.
        </p>
      </header>

      <Beat
        step={1}
        kicker="The haystack"
        title={`Of ${count(haystack.published)} vulnerabilities published in ${haystack.year}, ${haystack.listed} reached the KEV list by year end`}
      >
        <p className="mb-3 text-5xl font-semibold">
          1 in {Math.round(haystack.published / haystack.listed)}
        </p>
        <HaystackField
          published={haystack.published}
          listed={haystack.listed}
          year={haystack.year}
        />
        <Note>
          One dot per vulnerability. The highlighted dots are placed at random; their positions are
          not data.
        </Note>
      </Beat>

      <Beat
        step={2}
        kicker="The obvious answer"
        title={`Critical is riskier, but ${percent(1 - critical.listed / critical.published, 1)} of Critical vulnerabilities weren't on the list by the end of 2025`}
      >
        <SeverityBars
          rows={severity}
          caption={
            <Note>
              Share on the KEV list, for vulnerabilities published through 2025 with a CVSS 3
              severity. KEV starts in November 2021, and severity scores are NIST's current
              versions.
            </Note>
          }
        />
        <p className="mt-4 text-sm">
          Weakness type separates them more sharply. Cross-site scripting is the most common, with{" "}
          {count(weakness.xss.published)} vulnerabilities and {weakness.xss.listed} listed (
          {percent(weakness.xss.listed / weakness.xss.published, 2)}). Type confusion has{" "}
          {count(weakness.typeConfusion.published)}, with {weakness.typeConfusion.listed} listed (
          {percent(weakness.typeConfusion.listed / weakness.typeConfusion.published, 1)}). NIST
          assigns weakness types during review, so most new vulnerabilities don't have one yet.
        </p>
      </Beat>

      <Beat
        step={3}
        kicker="Two different races"
        title="Some listings arrive within days of publication and others years later, so there isn't one warning window"
      >
        <LagColumns
          bins={lag.bins}
          total={lag.total}
          caption={
            <Note>
              Days from NIST publication to KEV listing, for {lag.total} vulnerabilities listed in
              2024 and 2025. The bins have unequal widths.
            </Note>
          }
        />
        <h3 className="mt-8 mb-2 text-sm font-semibold">
          What was visible at the last month-end before listing
        </h3>
        <VisibilityBar
          total={visible}
          parts={[
            {
              label: "Not yet published",
              count: visibility.notPublished,
              className: "bg-(--story-s3)",
            },
            {
              label: "Published, no data",
              count: visibility.noData,
              className: "bg-muted-foreground/50",
            },
            { label: "Quiet", count: visibility.quiet, className: "bg-(--story-s2)" },
            { label: "Loud", count: visibility.loud, className: "bg-(--story-s1)" },
          ]}
          caption={
            <Note>
              {visible} listings from {monthName(visibility.from)} to {monthName(visibility.to)}.
              Loud means public exploit code or an EPSS score of at least 10%, and quiet means
              neither. For scale, {percent(visibility.unlistedLoudShareDec2024)} of unlisted
              vulnerabilities in the December 2024 snapshot were loud. The snapshots are monthly, so
              a vulnerability published on the 1st and listed on the 28th counts as not yet
              published.
            </Note>
          }
        />
        <p className="mt-4 text-sm">
          For {percent(visibility.notPublished / visible)}, the last monthly snapshot before listing
          came before publication, so a ranking built on monthly signals would have had nothing to
          go on. The description is the one field every new vulnerability has from the start.
        </p>
      </Beat>

      <Beat
        step={4}
        kicker="The alarm"
        title="For older vulnerabilities, the EPSS score sat flat for six months, then jumped in the month of listing"
      >
        <EpssLine
          points={epss.medians}
          caption={
            <Note>
              Median EPSS for {epss.cohort} vulnerabilities listed from {monthName(epss.from)} to{" "}
              {monthName(epss.to)} and published before the six months shown began:{" "}
              {percent(before.median, 1)} the month before listing, {percent(during.median)} the
              month of it. This window avoids EPSS's March 2025 model change, which adds a false
              step to wider groups. Monthly data can't show whether the jump came just before or
              just after listing, and a listing date isn't when attacks began. Not every case looks
              like this: for the {epss.counterexample.cohort} chosen the same way and listed in{" "}
              {monthName(epss.counterexample.month)}, the median stayed between{" "}
              {percent(epss.counterexample.low)} and {percent(epss.counterexample.high)} throughout.
            </Note>
          }
        />
      </Beat>

      <footer className="mt-4 rounded-lg border p-4 text-xs text-muted-foreground">
        <p className="font-semibold text-foreground">About the data</p>
        <p className="mt-1">
          NIST NVD, CISA KEV, FIRST EPSS and public exploit flags from the IBM track dataset. The
          KEV list here ends on December 31, 2025, so later listings are not counted, and a
          vulnerability missing from KEV may still have been attacked. NIST fields are today's
          versions. Rebuild these numbers with <code>scripts/build_story_data.py</code>.
        </p>
      </footer>
    </main>
  );
}
