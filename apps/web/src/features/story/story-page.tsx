import { type ReactNode, useState } from "react";

import { count } from "./chart-kit";
import {
  AucDots,
  CatchCurve,
  CatchCurveLegend,
  Dossier,
  FEATURE_LABEL,
  GateBars,
  GateLegend,
  GraniteCells,
  HBars,
  data,
  exactInterval,
} from "./charts";
import {
  EpssSpark,
  HAYSTACK,
  LAG_PARTS,
  NeedleDots,
  PairBars,
  SEVERITY_PARTS,
  SplitBar,
  Waffle,
} from "./problem-visuals";

// The story page's series colors, checked for color-blind separation on the app's light and dark backgrounds.
const SERIES =
  "[--story-s1:#2a78d6] [--story-s2:#1baf7a] [--story-s3:#eb6834] dark:[--story-s1:#3987e5] dark:[--story-s2:#199e70] dark:[--story-s3:#d95926]";

function Beat({
  step,
  kicker,
  title,
  children,
}: {
  step: number;
  kicker?: string;
  title: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="border-b py-10 last:border-b-0">
      <p className="text-xs font-semibold text-muted-foreground">
        {step}.{kicker ? ` ${kicker}` : ""}
      </p>
      <h2 className="mt-1 mb-5 text-xl leading-snug font-semibold text-balance">{title}</h2>
      {children}
    </section>
  );
}

const Note = ({ children }: { children: ReactNode }) => (
  <p className="mt-3 text-xs text-muted-foreground">{children}</p>
);

const Ext = ({ href, children }: { href: string; children: ReactNode }) => (
  <a href={href} target="_blank" rel="noopener noreferrer" className="underline underline-offset-2">
    {children}
  </a>
);

function Stat({
  value,
  children,
  source,
  visual,
}: {
  value: string;
  children: ReactNode;
  source?: ReactNode;
  visual?: ReactNode;
}) {
  return (
    <div className="grid min-w-0 content-start gap-0.5">
      <span className="text-3xl font-semibold tabular-nums">{value}</span>
      <span className="text-sm">{children}</span>
      {visual}
      {source && <span className="mt-1 text-xs text-muted-foreground">{source}</span>}
    </div>
  );
}

const Term = ({ children }: { children: ReactNode }) => (
  <span className="font-semibold text-foreground">{children}</span>
);

function Card({
  title,
  children,
  source,
}: {
  title: string;
  children: ReactNode;
  source?: ReactNode;
}) {
  return (
    <div className="grid min-w-0 content-start gap-1.5 rounded-lg border bg-card p-4">
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="text-sm text-muted-foreground">{children}</p>
      {source && <span className="text-xs text-muted-foreground">{source}</span>}
    </div>
  );
}

const money = (v: number) =>
  "$" +
  (v >= 1e6
    ? (v / 1e6).toFixed(2) + "M"
    : v >= 1e4
      ? Math.round(v / 1e3) + "K"
      : Math.round(v).toLocaleString("en-US"));

// Measured on CVEs published January–September 2025: both strategies catch the same 21 exploited CVEs.
const ALTERNATIVE = { name: "Patch every CVSS 9+", reviews: 4682, caught: 21 };
const OURS = { name: "PatchRader", reviews: 597, caught: 21 };

function Slider({
  id,
  label,
  value,
  min,
  max,
  step,
  display,
  onChange,
}: {
  id: string;
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  display: string;
  onChange: (v: number) => void;
}) {
  return (
    <label htmlFor={id} className="grid gap-1.5">
      <span className="flex items-baseline justify-between text-xs font-semibold text-muted-foreground">
        {label}
        <span className="text-base font-semibold text-foreground tabular-nums">{display}</span>
      </span>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full accent-(--story-s1)"
      />
      <span className="flex justify-between text-[11px] text-muted-foreground tabular-nums">
        <span>{min}</span>
        <span>{max}</span>
      </span>
    </label>
  );
}

function CostCompare() {
  const [hours, setHours] = useState(2);
  const [rate, setRate] = useState(100);
  const side = (s: typeof OURS, ours: boolean) => {
    const cost = s.reviews * hours * rate;
    return { ...s, ours, cost, perCatch: cost / s.caught };
  };
  const alt = side(ALTERNATIVE, false);
  const us = side(OURS, true);
  const saved = alt.cost - us.cost;
  const less = 1 - us.reviews / alt.reviews;

  return (
    <>
      <div className="mt-6 grid gap-5 sm:grid-cols-2">
        <Slider
          id="cost-hours"
          label="Hours per CVE"
          value={hours}
          min={0.5}
          max={8}
          step={0.5}
          display={`${hours} h`}
          onChange={setHours}
        />
        <Slider
          id="cost-rate"
          label="Cost per hour ($)"
          value={rate}
          min={25}
          max={300}
          step={5}
          display={`$${rate}`}
          onChange={setRate}
        />
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        {[alt, us].map((s) => (
          <div
            key={s.name}
            className={`grid content-start gap-1 rounded-lg border p-4 ${s.ours ? "border-(--story-s1)" : ""}`}
          >
            <span className="text-sm font-semibold">{s.name}</span>
            <span
              className={`text-4xl font-semibold tabular-nums ${s.ours ? "text-(--story-s1)" : ""}`}
            >
              {money(s.cost)}
            </span>
            <span className="text-sm text-muted-foreground tabular-nums">
              {count(s.reviews)} CVEs are reviewed to catch {s.caught} exploited cases
            </span>
            <span className="text-xs text-muted-foreground tabular-nums">
              {money(s.perCatch)} to catch a CVE that becomes KEV
            </span>
          </div>
        ))}
      </div>

      <div className="mt-5 grid gap-2" aria-hidden="true">
        {[alt, us].map((s) => (
          <div key={s.name} className="grid grid-cols-[8.5rem_minmax(0,1fr)] items-center gap-3">
            <span className="text-xs text-muted-foreground">{s.name}</span>
            <span
              className={`block h-4 rounded-r ${s.ours ? "bg-(--story-s1)" : "bg-muted-foreground/60"}`}
              style={{ width: `${Math.max(1, (100 * s.cost) / alt.cost)}%` }}
            />
          </div>
        ))}
      </div>

      <p className="mt-5 text-sm">
        Same {us.caught} exploited CVEs caught, <b>{money(saved)} less labor</b> and{" "}
        <b>{Math.round(100 * less)}% fewer reviews</b> ({count(alt.reviews - us.reviews)} CVEs your
        team doesn't have to touch). Given the full 4,682-review workload, our model catches{" "}
        <b>39 instead of 21</b>.
      </p>
    </>
  );
}

const VENDORS: [string, number][] = [
  ["Apache", 82],
  ["Microsoft", 63],
  ["Google", 19],
  ["Cisco", 7],
  ["Ivanti", 7],
  ["Oracle", 7],
  ["Fortinet", 6],
  ["VMware", 5],
  ["Palo Alto Networks", 4],
  ["Red Hat / IBM", 3],
];

export function StoryPage() {
  const C = data.curve;
  const caught = C.series.model[C.ks.indexOf(C.k)]!;
  const release = data.release.map((r) => {
    const v = (1000 * r.exploited) / r.cves;
    const ci = exactInterval(r.exploited, r.cves).map((p) => p * 1000) as [number, number];
    const label = r.label === "1" ? "Alone" : `${r.label} CVEs`;
    return { r, v, ci, label };
  });

  return (
    <main className={`mx-auto w-full min-w-0 max-w-3xl px-4 pt-8 pb-16 ${SERIES}`}>
      <header className="pb-2">
        <p className="text-xs font-semibold text-muted-foreground">PatchRader</p>
        <h1 className="mt-1 text-3xl font-semibold text-balance">Story</h1>
        <p className="mt-3 max-w-2xl text-sm text-muted-foreground">
          A <Term>CVE</Term> (Common Vulnerabilities and Exposures) is a public ID for one specific
          security flaw, such as CVE-2026-2699. Tens of thousands are published every year.{" "}
          <Term>KEV</Term> (Known Exploited Vulnerabilities) is CISA's list of CVEs with confirmed
          attacks in the wild. US federal agencies must patch them by a deadline, and this
          competition asks which 2026 CVEs CISA will add next.
        </p>
        <p className="mt-3 max-w-2xl text-sm text-muted-foreground">
          Two scores come up throughout. <Term>CVSS</Term> (Common Vulnerability Scoring System)
          rates how severe a flaw would be on a 0–10 scale, with 9.0 and above rated Critical; it
          doesn't say how likely an attack is. <Term>EPSS</Term> (Exploit Prediction Scoring System)
          is FIRST's daily estimate of the chance a CVE is exploited in the next 30 days.
        </p>
      </header>

      <Beat
        step={1}
        title="Exploited vulnerabilities are now the most common way breaches start, and defenders can't patch everything"
      >
        <div className="grid gap-x-6 gap-y-5 sm:grid-cols-2">
          <Stat
            value="$4.99M"
            visual={
              <PairBars
                label="Average breach cost: $4.44M in IBM's 2025 report, $4.99M in 2026"
                rows={[
                  ["2025 report", 4.44],
                  ["2026 report", 4.99],
                ]}
                max={6}
                format={(v) => `$${v.toFixed(2)}M`}
              />
            }
            source={
              <Ext href="https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average">
                IBM Cost of a Data Breach 2026
              </Ext>
            }
          >
            average cost of a data breach
          </Stat>
          <Stat
            value="31%"
            visual={
              <PairBars
                label="Breaches that began with an exploited vulnerability: 20% in the 2025 report, 31% in 2026"
                rows={[
                  ["2025 report", 20],
                  ["2026 report", 31],
                ]}
                max={100}
                format={(v) => `${v}%`}
              />
            }
            source={
              <Ext href="https://www.helpnetsecurity.com/2026/05/20/verizon-2026-dbir-findings/">
                Verizon DBIR 2026
              </Ext>
            }
          >
            of breaches began with an exploited vulnerability, now the top way in (up from 20%)
          </Stat>
          <Stat
            value="26%"
            visual={
              <Waffle
                filled={26}
                label="26 of every 100 known-exploited vulnerabilities fully fixed"
              />
            }
            source={
              <Ext href="https://www.scworld.com/news/verizon-dbir-2026-vulnerability-exploits-top-initial-access-as-patching-coverage-falls">
                Verizon DBIR 2026
              </Ext>
            }
          >
            of known-exploited vulnerabilities were fully fixed in 2026
          </Stat>
        </div>
        <h3 className="mt-8 mb-3 text-sm font-semibold">What we found in NIST</h3>
        <div className="grid gap-x-6 gap-y-5 sm:grid-cols-2">
          <Stat
            value="1 in 292"
            visual={
              <NeedleDots
                total={Math.round(HAYSTACK.published / HAYSTACK.listed)}
                label="One highlighted dot among 292"
              />
            }
          >
            CVEs published in 2025 became KEV by the end of the year: 165 of 48,150
          </Stat>
          <Stat
            value="66%"
            visual={
              <SplitBar
                parts={SEVERITY_PARTS}
                highlight="Not Critical"
                label="KEV-listed CVEs by severity: two-thirds not rated Critical"
              />
            }
          >
            of KEV-listed CVEs weren't rated Critical, and 98.5% of Critical CVEs never reached KEV
          </Stat>
          <Stat
            value="30%"
            visual={
              <SplitBar
                parts={LAG_PARTS}
                highlight="Over 6 months"
                label="Time from CVE publication to KEV listing"
              />
            }
          >
            of KEV listings came more than 6 months after being published as a CVE
          </Stat>
          <Stat
            value="10×"
            visual={
              <EpssSpark label="Median EPSS stays flat for six months, then jumps in the month of KEV listing" />
            }
          >
            increase in EPSS in the month a CVE was listed (2.6% → 26%), after six months
          </Stat>
        </div>
      </Beat>

      <Beat
        step={2}
        kicker="The cost"
        title="Every patching rule fails in one of two expensive ways: it misses an exploited CVE, or it buries the team in work"
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Card title="Consquences of Missed CVEs">
            Exploits are the start of a third of breaches, and the average breach costs $4.99M alone
            without considering downtime and lost customers.
          </Card>
          <Card title="Misplaced Resources">
            Patching every CVE rated CVSS 9+ meant 4,682 CVEs in nine months of 2025. Each needs
            triage, testing and a change window, and the exploited ones wait in the same queue.
          </Card>
        </div>
        <CostCompare />
        <Note>
          One test year with 52 exploited CVEs, so small differences could be luck. Labor figures
          depend entirely on the two slider values. IBM's $4.99M is an average over all breaches,
          not the cost of one missed CVE.
        </Note>
      </Beat>

      <Beat
        step={3}
        kicker="Why it matters to IBM"
        title="IBM is on every side of this problem: it builds the software, runs it for clients and sells the defense"
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Card
            title="IBM's own software"
            source={
              <>
                Competition KEV data;{" "}
                <Ext href="https://darkreading.com/vulnerabilities-threats/patch-now-cybercriminals-set-sights-critical-ibm-file-transfer-bug">
                  Dark Reading
                </Ext>
              </>
            }
          >
            7 IBM products are on KEV, and 2 were used by ransomware gangs. Aspera Faspex
            (CVE-2022-47986, CVSS 9.8, no login needed) was exploited by IceFire and Buhti, and CISA
            listed it 4 days after publication. Red Hat, an IBM company, has 7 more, including
            Polkit's CVE-2021-4034, listed 150 days after publication: the slow kind our model is
            built to catch early.
          </Card>
          <Card
            title="Software IBM runs for clients"
            source={
              <>
                <Ext href="https://www.securityweek.com/colorado-health-agency-says-4-million-impacted-by-moveit-hack/">
                  SecurityWeek
                </Ext>
                ;{" "}
                <Ext href="https://beckershospitalreview.com/healthcare-information-technology/cybersecurity/healthcare-data-breaches-cost-6-64m-on-average-report">
                  Becker's
                </Ext>
                ;{" "}
                <Ext href="https://www.northdoor.co.uk/about-us/resources/cost-of-a-data-breach-financial-services-2026/">
                  Northdoor
                </Ext>
              </>
            }
          >
            In 2023, attackers exploited MOVEit Transfer, third-party software IBM ran for
            Colorado's Medicaid agency, exposing 4 million people's health data. IBM's 2026 report
            puts the average breach at $6.64M in healthcare and $6.29M in financial services, two of
            IBM's largest client industries.
          </Card>
          <Card
            title="IBM's own threat data"
            source={
              <Ext href="https://newsroom.ibm.com/2026-02-25-ibm-2026-x-force-threat-index-ai-driven-attacks-are-escalating-as-basic-security-gaps-leave-enterprises-exposed?asPDF=1">
                IBM X-Force Threat Intelligence Index 2026
              </Ext>
            }
          >
            40% of incidents IBM X-Force observed in 2025 started with an exploited vulnerability,
            and attacks that began by exploiting public-facing applications rose 44%.
          </Card>
          <Card title="IBM as a CVE publisher" source="Competition scoreboard; outputs/top500.csv">
            IBM, Red Hat and HashiCorp issued 2,317 of the 2026 scoreboard's CVEs (3.2%). Our list
            flags 10 of them, 8 from Red Hat and 2 from IBM, the highest at ranks 22 and 25: a short
            list for IBM's product-security teams to push customers to patch first.
          </Card>
        </div>
        <h3 className="mt-8 mb-2 text-sm font-semibold">
          Enterprise software named most in our 2026 top 500
        </h3>
        <HBars
          label="Vendors named in our top 500"
          rows={VENDORS.map(([l, n]) => ({
            label: l,
            value: n,
            text: String(n),
            tip: [["CVEs in our top 500", String(n)]],
          }))}
          table={{ head: ["Vendor", "CVEs in our top 500"], rows: VENDORS }}
        />
        <Note>Counted from CVE descriptions; one CVE can name more than one vendor.</Note>
        <p className="mt-4 text-sm">
          <b>Where PatchRader could fit.</b> IBM Concert scores CVE risk by combining CVSS with
          EPSS, according to an{" "}
          <Ext href="https://community.ibm.com/community/user/blogs/aidan-mitchell/2026/06/23/why-risk-based-vulnerability-management-matters">
            IBM community post
          </Ext>
          . In our tests both were weak for new CVEs (sections 4 and 8). PatchRader already runs on
          IBM Granite and could add a third signal: a daily list of the few new CVEs most likely to
          be exploited, each with its reasons. This is a proposal; PatchRader isn't integrated with
          any IBM product today.
        </p>
      </Beat>

      <Beat
        step={4}
        kicker="Our answer"
        title={`Trained only on 2024, the model caught ${caught} of the ${C.positives} CVEs from 2025 that CISA later listed, by reviewing 0.69% of them`}
      >
        <p className="mb-3 text-5xl font-semibold tabular-nums">
          {caught}
          <span className="ml-2 text-lg font-medium text-muted-foreground">
            of {C.positives} caught in the top {C.k}
          </span>
        </p>
        <CatchCurveLegend />
        <CatchCurve />
        <Note>
          Exploited CVEs caught as you work down each ranking of the {count(C.n)} CVEs published
          January–September 2025. The dashed line is the submission's budget; the orange point is
          "patch every CVSS 9+". With {C.positives} exploited CVEs, gaps under about 6 could be
          luck. Repeated cross-validation on 2024–2025 gives the same order: 36.4 caught vs. 22 for
          exploit code, then EPSS.
        </Note>
      </Beat>

      <Beat
        step={5}
        kicker="The issuer gate"
        title="Established issuers that have never had a KEV entry almost never get one: 1 of their 32,113 CVEs in four years"
      >
        <GateLegend />
        <GateBars />
        <Note>
          Exploited per 1,000 CVEs, with exact 95% intervals. "Large" means 200 or more earlier
          CVEs; these issuers publish 22–38% of all CVEs each year.
        </Note>
        <p className="mt-4 text-sm">
          No history isn't the same as safe. New or small issuers with no KEV history, often vendors
          that just started issuing their own CVEs (JetBrains TeamCity, Progress WS_FTP, ConnectWise
          ScreenConnect), are as risky as everyone else. That split was found by studying the
          failures, so it needs 2026 labels to confirm.
        </p>
      </Beat>

      <Beat
        step={6}
        kicker="Release size"
        title="A CVE published alone is far likelier to be exploited than one in a large patch batch"
      >
        <HBars
          label="Exploited per 1,000 CVEs by release size"
          labelWidth={90}
          max={11}
          axis={[0, 2, 4, 6, 8, 10]}
          rows={release.map(({ r, v, ci, label }) => ({
            label,
            value: v,
            ci,
            text: v.toFixed(2),
            tip: [
              ["Exploited", `${r.exploited} of ${count(r.cves)}`],
              ["Per 1,000", v.toFixed(2)],
              ["95% interval", `${ci[0].toFixed(2)}–${ci[1].toFixed(2)}`],
            ],
          }))}
          table={{
            head: ["Release size", "CVEs", "Exploited", "Per 1,000"],
            rows: release.map(({ r, v, label }) => [
              label,
              count(r.cves),
              r.exploited,
              v.toFixed(2),
            ]),
          }}
        />
        <Note>
          Exploited per 1,000 CVEs by how many CVEs the same issuer published that day, 2024–2025
          backtest (64,120 CVEs, 85 exploited). Exact 95% intervals.
        </Note>
        <p className="mt-4 text-sm">
          Within the same issuer, releases of 1–3 CVEs had 5.2 times the odds of reaching KEV (95%
          CI 2.9–9.3), and they reached it faster: a median of 48 days vs. 73.
        </p>
      </Beat>

      <Beat
        step={7}
        kicker="What the model weighs"
        title="Who issued the CVE matters most, then release size and the IBM Granite text score"
      >
        <HBars
          label="Share of SHAP importance"
          labelWidth={190}
          rows={data.importance.map((f) => ({
            label: FEATURE_LABEL[f.feature] ?? f.feature,
            value: f.share,
            text: `${(100 * f.share).toFixed(1)}%`,
            tip: [["Share of SHAP", `${(100 * f.share).toFixed(1)}%`]],
          }))}
          table={{
            head: ["Feature", "Share"],
            rows: data.importance.map((f) => [
              FEATURE_LABEL[f.feature] ?? f.feature,
              `${(100 * f.share).toFixed(1)}%`,
            ]),
          }}
        />
        <Note>
          Share of the LightGBM model's average absolute SHAP contribution over 2024–2025 training
          CVEs. Public exploit code ranks 7th on average but pushes hardest inside the 2026 top 500.
          These show what the model relies on, not what causes exploitation.
        </Note>
      </Beat>

      <Beat
        step={8}
        kicker="Timing and text"
        title="EPSS at publication was no better than chance in 2024, and IBM Granite changed 110 of our 500 picks"
      >
        <AucDots />
        <Note>
          AUC of EPSS at the end of each CVE's publication month for separating later-exploited CVEs
          from the rest (0.5 is random), with 95% intervals where the window allows. The 2025 rise
          coincides with the March 2025 EPSS update; we haven't tested whether it's the cause.
        </Note>
        <h3 className="mt-8 mb-2 text-sm font-semibold">Our 2026 list, one square per CVE</h3>
        <GraniteCells />
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <span className="inline-block size-2.5 rounded-sm bg-(--story-s1)" />
            in the list only because of the Granite text score ({500 - data.granite.kept})
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block size-2.5 rounded-sm bg-border" />
            also picked without it ({data.granite.kept})
          </span>
        </div>
        <Note>
          Any "exploited in the wild" wording is removed before Granite reads a description.
        </Note>
      </Beat>

      <Beat step={9} kicker="The submission" title="Why each CVE is on the list">
        <Dossier />
        <Note>
          Bars show how each input pushed the CVE's LightGBM score up (blue) or down (orange), in
          log-odds.
        </Note>
      </Beat>

      <footer className="mt-4 rounded-lg border p-4 text-xs text-muted-foreground">
        <p className="font-semibold text-foreground">About the data</p>
        <ul className="mt-1 list-disc space-y-1 pl-4">
          <li>
            NIST NVD, CISA KEV, FIRST EPSS and public exploit flags from the IBM track dataset;
            industry figures from the reports linked above.
          </li>
          <li>
            2026 results don't exist yet. Every hit count comes from backtests on 2024 and 2025.
          </li>
          <li>
            Model inputs are point-in-time: only what was known at the end of each CVE's publication
            month. NIST review fields, affected products and reference counts are never used.
          </li>
          <li>
            The analysis behind each number is in <code>notebooks/</code>: issuer_gate_tests,
            shap_interpretation and final_model_with_granite.
          </li>
        </ul>
      </footer>
    </main>
  );
}
