import type { AuditReport } from "../types";
import { xmlEscape } from "../utils/escape";
import { summarizePackageDecisions } from "../policies/policy-engine";

export function toJUnitXml(
  report: AuditReport,
  opts?: { failOnWarn?: boolean },
): string {
  const failOnWarn = opts?.failOnWarn ?? false;

  let failures = 0;
  let skipped = 0;
  const cases: string[] = [];

  for (const p of report.packages) {
    const name = `${p.pkg.name}@${p.pkg.version}`;
    const { blocked, warned } = summarizePackageDecisions(p);

    const relevantDecisions = p.decisions.filter(
      (d) => d.action === (blocked ? "block" : warned ? "warn" : "allow"),
    );
    const msg = relevantDecisions
      .map((d) => `${d.source}: ${d.reason}${d.findingId ? ` (${d.findingId})` : ""}`)
      .join("\n");

    if (blocked) {
      failures++;
      cases.push(
        `<testcase classname="pnpm-audit" name="${xmlEscape(name)}"><failure message="blocked">${xmlEscape(msg)}</failure></testcase>`,
      );
    } else if (warned) {
      if (failOnWarn) {
        failures++;
        cases.push(
          `<testcase classname="pnpm-audit" name="${xmlEscape(name)}"><failure message="warning treated as failure">${xmlEscape(msg)}</failure></testcase>`,
        );
      } else {
        skipped++;
        cases.push(
          `<testcase classname="pnpm-audit" name="${xmlEscape(name)}"><skipped message="warnings">${xmlEscape(msg)}</skipped></testcase>`,
        );
      }
    } else {
      cases.push(`<testcase classname="pnpm-audit" name="${xmlEscape(name)}" />`);
    }
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="pnpm-audit" tests="${report.packages.length}" failures="${failures}" skipped="${skipped}">
${cases.join("\n")}
</testsuite>
`;
}
