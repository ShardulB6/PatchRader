const TERMS = [
  {
    term: "KEV",
    full: "Known Exploited Vulnerabilities",
    meaning:
      "The list kept by CISA, the US cybersecurity agency, of vulnerabilities confirmed to be under attack. A vulnerability is “listed” once it is added. The list began in November 2021.",
  },
  {
    term: "CVE",
    full: "Common Vulnerabilities and Exposures",
    meaning:
      "The standard ID for a publicly disclosed vulnerability, such as CVE-2024-3094. Each vulnerability counted on this page is one CVE.",
  },
  {
    term: "EPSS",
    full: "Exploit Prediction Scoring System",
    meaning:
      "An estimate from FIRST, a global incident response group, of the chance that a vulnerability will be exploited in the next 30 days, from 0 to 100%.",
  },
  {
    term: "CVSS",
    full: "Common Vulnerability Scoring System",
    meaning:
      "A severity rating from 0 to 10: Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9) or Critical (9.0–10). It describes how serious a flaw is, not whether anyone is attacking it.",
  },
  {
    term: "NVD",
    full: "National Vulnerability Database",
    meaning:
      "The US public vulnerability database, run by NIST, the National Institute of Standards and Technology. This page's publication dates, severity scores and weakness types come from it.",
  },
  {
    term: "Weakness type",
    full: "CWE, Common Weakness Enumeration",
    meaning: "The kind of mistake behind a vulnerability, from a standard catalog of categories.",
  },
  {
    term: "Cross-site scripting",
    full: "a weakness type",
    meaning: "A flaw that lets an attacker run their own script in a visitor's browser.",
  },
  {
    term: "Type confusion",
    full: "a weakness type",
    meaning:
      "A flaw where a program treats data in memory as the wrong kind of object, which can let an attacker take control of it.",
  },
  {
    term: "Loud and quiet",
    full: "this page's own labels",
    meaning:
      "Loud means working exploit code is public (on Exploit-DB, Metasploit, Nuclei or GitHub) or EPSS is at least 10%. Quiet means neither.",
  },
];

/** A glossary of the abbreviations and labels the story uses. */
export function KeyTerms() {
  return (
    <details open className="mt-6 rounded-lg border p-4 text-xs">
      <summary className="cursor-pointer font-semibold select-none">Key terms</summary>
      <dl className="mt-3 grid gap-x-6 gap-y-3 sm:grid-cols-2">
        {TERMS.map(({ term, full, meaning }) => (
          <div key={term}>
            <dt>
              <span className="font-semibold">{term}</span>
              <span className="text-muted-foreground"> · {full}</span>
            </dt>
            <dd className="mt-0.5 text-muted-foreground">{meaning}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
