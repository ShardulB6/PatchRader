export type Flow = "story" | "ai" | "impact";

export type DiagramItem = {
  id: string;
  title: string;
  subtitle: string;
  x: number;
  y: number;
  w: number;
  h: number;
  flows: readonly Flow[];
  details: readonly string[];
  path?: string;
  subtitle2?: string;
  mono?: boolean;
  kind?: "file" | "unused";
};

export type DiagramGroup = DiagramItem & {
  labelX: number;
  labelY: number;
  subtitleY?: number;
};

export type DiagramEdge = {
  points: readonly (readonly [number, number])[];
  flows: readonly Flow[];
  unused?: boolean;
  label?: { text: string; x: number; y: number; end?: boolean };
};

const ALL = ["story", "ai", "impact"] as const;
const API = ["ai", "impact"] as const;
const STORY = ["story"] as const;
const AI = ["ai"] as const;
const IMPACT = ["impact"] as const;

export const FLOW_NAMES: Record<Flow, string> = {
  story: "Story page",
  ai: "AI Analyst",
  impact: "Impact page",
};

export const GROUPS: readonly DiagramGroup[] = [
  {
    id: "web",
    title: "Web app",
    subtitle: "TanStack Start, srvx on :3000",
    x: 12,
    y: 452,
    w: 216,
    h: 184,
    labelX: 24,
    labelY: 472,
    subtitleY: 488,
    flows: ALL,
    path: "apps/web",
    details: [
      "The dashboard. TanStack Start renders it and srvx serves the built app on 127.0.0.1:3000, read-only and sandboxed.",
      "Shared components come from packages/ui.",
    ],
  },
  {
    id: "api",
    title: "AI Analyst API",
    subtitle: "FastAPI on :8000",
    x: 259,
    y: 452,
    w: 457,
    h: 184,
    labelX: 478,
    labelY: 472,
    flows: API,
    path: "backend/",
    details: [
      "The Python service behind the AI Analyst and Impact pages. It runs under uvicorn on 127.0.0.1:8000 with a single worker.",
      "Only /api/* is exposed publicly.",
    ],
  },
];

export const NODES: readonly DiagramItem[] = [
  {
    id: "release",
    title: "GitHub release data-v1",
    subtitle: "NVD, KEV, EPSS, cvss-bt, CWE",
    x: 0,
    y: 24,
    w: 216,
    h: 62,
    flows: ALL,
    details: [
      "The IBM track dataset. It is too large for git, so it is stored as a GitHub release.",
      "It combines NIST NVD, CISA KEV, FIRST EPSS, cvss-bt and MITRE CWE.",
    ],
  },
  {
    id: "data",
    title: "data/",
    mono: true,
    subtitle: "850 MB of CSVs, gitignored",
    subtitle2: "fetched by scripts/fetch_data.py",
    x: 256,
    y: 24,
    w: 216,
    h: 62,
    flows: ALL,
    path: "data/",
    details: [
      "Download it once per checkout with python3 scripts/fetch_data.py.",
      "Column details are in data/DATA_DICTIONARY.md.",
    ],
  },
  {
    id: "tiger",
    title: "Tiger Cloud",
    subtitle: "exploit_signals table",
    subtitle2: "no page queries it yet",
    x: 512,
    y: 24,
    w: 216,
    h: 62,
    kind: "unused",
    flows: [],
    details: [
      "Postgres holding the monthly exploit signals and the 2026 scoreboard values, with a source column telling them apart.",
      "It also stores the Granite embeddings used by the vector search notebook. The live site does not read from it.",
    ],
  },
  {
    id: "story-script",
    title: "build_story_data.py",
    mono: true,
    subtitle: "turns CSVs into chart series",
    x: 0,
    y: 118,
    w: 216,
    h: 52,
    flows: STORY,
    path: "scripts/build_story_data.py",
    details: [
      "Reads the KEV list, vulnerabilities and monthly signals, then writes the series behind every chart on the story page.",
    ],
  },
  {
    id: "story-json",
    title: "story-data.json",
    mono: true,
    subtitle: "every number on the story page",
    x: 0,
    y: 188,
    w: 216,
    h: 52,
    kind: "file",
    flows: STORY,
    path: "apps/web/src/features/story/story-data.json",
    details: [
      "Committed to git and imported directly by the story page, so the page needs no API or database.",
    ],
  },
  {
    id: "features",
    title: "ml/data.py, featureset.py",
    mono: true,
    subtitle: "builds the model features",
    x: 256,
    y: 118,
    w: 216,
    h: 52,
    flows: IMPACT,
    path: "ml/data.py, ml/featureset.py",
    details: [
      "data.py loads the CSVs into DuckDB and builds the labeled sets. featureset.py wraps the team features in scripts/features.py and scripts/features_extra.py.",
      "Exploit signals and history features use only what was known at the end of the CVE's publication month. Description, CVSS and CWE fields come from current NVD records, so they can include later edits.",
    ],
  },
  {
    id: "text-scores",
    title: "ml/text_scores/",
    mono: true,
    subtitle: "adds precomputed Granite scores",
    x: 256,
    y: 188,
    w: 216,
    h: 52,
    kind: "file",
    flows: IMPACT,
    path: "ml/text_scores/frozen-small/",
    details: [
      "Four committed score files from frozen IBM Granite embeddings plus a logistic regression.",
      "Committing them lets the final model reproduce without about an hour of GPU time.",
    ],
  },
  {
    id: "final-model",
    title: "ml/final_model.py",
    mono: true,
    subtitle: "LR + LightGBM, 50/50 rank blend",
    x: 256,
    y: 258,
    w: 216,
    h: 52,
    flows: IMPACT,
    path: "ml/final_model.py",
    details: [
      "A 50/50 rank blend of logistic regression and LightGBM, trained on CVEs published January to September of 2024 and 2025: 64,120 rows, 85 later added to KEV.",
      "Run python -m ml.final_model to reproduce the top 500 in a few minutes on a CPU.",
    ],
  },
  {
    id: "top500",
    title: "outputs/top500.csv",
    mono: true,
    subtitle: "the 500 CVEs we submitted",
    x: 256,
    y: 328,
    w: 216,
    h: 52,
    kind: "file",
    flows: IMPACT,
    path: "outputs/top500.csv",
    details: [
      "The submission. It ships with each release, and impact.py reads it for the Impact page, which is the only place the model reaches the site.",
    ],
  },
  {
    id: "load-signals",
    title: "load-signals.ts",
    mono: true,
    subtitle: "pnpm run db:load",
    x: 512,
    y: 118,
    w: 216,
    h: 52,
    kind: "unused",
    flows: [],
    path: "apps/web/scripts/load-signals.ts",
    details: [
      "Replaces the contents of the exploit_signals table with the monthly signals and the 2026 scoreboard values. Run it from apps/web.",
    ],
  },
  {
    id: "notebooks",
    title: "notebooks/",
    mono: true,
    subtitle: "24 experiments, made the scores",
    x: 512,
    y: 188,
    w: 216,
    h: 52,
    flows: IMPACT,
    path: "notebooks/",
    details: [
      "The research behind the model: backtests, Granite text experiments, diagnosis and SHAP analysis.",
      "trackb_5_frozen_handoff.ipynb produced the Granite scores the final model reads.",
    ],
  },
  {
    id: "page-story",
    title: "/story",
    mono: true,
    subtitle: "charts from the bundled JSON",
    x: 24,
    y: 498,
    w: 192,
    h: 38,
    flows: STORY,
    path: "apps/web/src/features/story/",
    details: ["The page the site opens on, because / redirects here. Its charts need no API call."],
  },
  {
    id: "page-ai",
    title: "/ai",
    mono: true,
    subtitle: "chat, through ai-client.ts",
    x: 24,
    y: 542,
    w: 192,
    h: 38,
    flows: AI,
    path: "apps/web/src/routes/ai.tsx",
    details: [
      "The chat page. It posts each question to /api/chat and draws the answer as text, rows and CVE cards.",
    ],
  },
  {
    id: "page-impact",
    title: "/impact",
    mono: true,
    subtitle: "cards, through ai-client.ts",
    x: 24,
    y: 586,
    w: 192,
    h: 38,
    flows: IMPACT,
    path: "apps/web/src/routes/impact.tsx",
    details: [
      "Shows the potential consequences of the top 500 CVEs, using data from /api/impact/top500.",
    ],
  },
  {
    id: "impact-py",
    title: "impact.py",
    mono: true,
    subtitle: "profiles the top 500",
    x: 271,
    y: 490,
    w: 186,
    h: 52,
    flows: IMPACT,
    path: "backend/impact.py",
    details: [
      "Reads outputs/top500.csv and looks up each CVE in the dataset through DuckDB.",
      "The result is cached until the file changes, so reloading the page does no extra work.",
    ],
  },
  {
    id: "db-py",
    title: "db.py",
    mono: true,
    subtitle: "DuckDB tables, predefined SQL",
    x: 482,
    y: 490,
    w: 222,
    h: 52,
    flows: API,
    path: "backend/db.py",
    details: [
      "Loads the CSVs into DuckDB, which takes about 1.6 GB of memory, and holds all the predefined SQL.",
      "Its priority queue sorts by public exploit signal, then EPSS. It does not use the ML model.",
    ],
  },
  {
    id: "api-py",
    title: "api.py",
    mono: true,
    subtitle: "routes, per-visitor rate limit",
    x: 271,
    y: 574,
    w: 186,
    h: 52,
    flows: API,
    path: "backend/api.py",
    details: [
      "Defines /health, /ready, /api/chat and /api/impact/top500.",
      "Each visitor gets 6 questions a minute by default.",
    ],
  },
  {
    id: "analyst-py",
    title: "analyst.py",
    mono: true,
    subtitle: "picks one fixed query per question",
    x: 482,
    y: 574,
    w: 222,
    h: 52,
    flows: AI,
    path: "backend/analyst.py",
    details: [
      "Turns a question into one predefined query, so the model never writes SQL. It asks watsonx.ai when available and uses a keyword router otherwise.",
      "It validates the model's choice before running anything.",
    ],
  },
  {
    id: "caddy",
    title: "Caddy",
    subtitle: "HTTPS on 443, routes by path",
    x: 130,
    y: 668,
    w: 228,
    h: 48,
    flows: ALL,
    path: "deploy/vultr/Caddyfile",
    details: [
      "Handles HTTPS for patchrader.health. It sends /api/* to FastAPI and everything else to the web app.",
    ],
  },
  {
    id: "browser",
    title: "Visitor's browser",
    subtitle: "/ redirects to /story",
    x: 130,
    y: 754,
    w: 228,
    h: 52,
    flows: ALL,
    details: [
      "Loads the web app from Caddy. The /ai and /impact pages then call /api/* on the same address.",
    ],
  },
  {
    id: "watsonx",
    title: "IBM watsonx.ai",
    subtitle: "picks the query, writes the summary",
    x: 482,
    y: 754,
    w: 222,
    h: 52,
    flows: AI,
    details: [
      "Optional. It defaults to meta-llama/llama-3-3-70b-instruct on a Toronto project, because Toronto does not offer Granite chat models.",
      "It handles at most 100 questions per UTC day by default. After that, or without credentials, the keyword router takes over and the answer is written from the rows.",
    ],
  },
];

export const EDGES: readonly DiagramEdge[] = [
  {
    points: [
      [216, 55],
      [256, 55],
    ],
    flows: ALL,
  },
  {
    points: [
      [364, 86],
      [364, 118],
    ],
    flows: IMPACT,
  },
  {
    points: [
      [364, 86],
      [364, 102],
      [108, 102],
      [108, 118],
    ],
    flows: STORY,
  },
  {
    points: [
      [364, 86],
      [364, 102],
      [580, 102],
      [580, 118],
    ],
    flows: [],
    unused: true,
  },
  {
    points: [
      [660, 118],
      [660, 86],
    ],
    flows: [],
    unused: true,
  },
  {
    points: [
      [512, 214],
      [472, 214],
    ],
    flows: IMPACT,
  },
  {
    points: [
      [364, 86],
      [364, 102],
      [492, 102],
      [492, 396],
      [593, 396],
      [593, 490],
    ],
    flows: API,
    label: { text: "copy in shared/data/", x: 601, y: 438 },
  },
  {
    points: [
      [108, 170],
      [108, 188],
    ],
    flows: STORY,
  },
  {
    points: [
      [108, 240],
      [108, 452],
    ],
    flows: STORY,
    label: { text: "bundled at build time", x: 116, y: 330 },
  },
  {
    points: [
      [364, 170],
      [364, 188],
    ],
    flows: IMPACT,
  },
  {
    points: [
      [364, 240],
      [364, 258],
    ],
    flows: IMPACT,
  },
  {
    points: [
      [364, 310],
      [364, 328],
    ],
    flows: IMPACT,
  },
  {
    points: [
      [364, 380],
      [364, 490],
    ],
    flows: IMPACT,
    label: { text: "ships with each release", x: 372, y: 438 },
  },
  {
    points: [
      [364, 574],
      [364, 542],
    ],
    flows: IMPACT,
  },
  {
    points: [
      [457, 516],
      [482, 516],
    ],
    flows: IMPACT,
  },
  {
    points: [
      [457, 600],
      [482, 600],
    ],
    flows: AI,
  },
  {
    points: [
      [593, 574],
      [593, 542],
    ],
    flows: AI,
  },
  {
    points: [
      [593, 626],
      [593, 754],
    ],
    flows: AI,
    label: { text: "optional, 100 questions a day", x: 585, y: 694, end: true },
  },
  {
    points: [
      [150, 668],
      [150, 636],
    ],
    flows: ALL,
    label: { text: "all other paths", x: 158, y: 656 },
  },
  {
    points: [
      [340, 668],
      [340, 626],
    ],
    flows: API,
    label: { text: "/api/*", x: 348, y: 656 },
  },
  {
    points: [
      [244, 754],
      [244, 716],
    ],
    flows: ALL,
    label: { text: "HTTPS", x: 252, y: 742 },
  },
];
