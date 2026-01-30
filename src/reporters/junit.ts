import type { AuditReport, PackageAuditResult, PolicyDecision } from "../types";

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function packageHasBlock(pkg: PackageAuditResult): boolean {
  return pkg.decisions.some((d) => d.action === "block");
}

function packageHasWarn(pkg: PackageAuditResult): boolean {
  return pkg.decisions.some((d) => d.action === "warn");
}

export function toJUnitXml(
  report: AuditReport,
  opts?: { failOnWarn?: boolean },
): string {
  const failOnWarn = opts?.failOnWarn ?? false;

  const total = report.packages.length;
  const failures =
    report.packages.filter(packageHasBlock).length +
    (failOnWarn
      ? report.packages.filter((p) => !packageHasBlock(p) && packageHasWarn(p))
          .length
      : 0);
  const skipped = !failOnWarn
    ? report.packages.filter((p) => !packageHasBlock(p) && packageHasWarn(p))
        .length
    : 0;

  const cases: string[] = [];

  for (const p of report.packages) {
    const name = `${p.pkg.name}@${p.pkg.version}`;
    const blocked = packageHasBlock(p);
    const warned = packageHasWarn(p);

    const relevantDecisions = p.decisions.filter(
      (d) => d.action === (blocked ? "block" : warned ? "warn" : "allow"),
    );

    if (blocked) {
      const msg = relevantDecisions
        .map(
          (d) =>
            `${d.source}: ${d.reason}${d.findingId ? ` (${d.findingId})` : ""}`,
        )
        .join("\n");

      cases.push(
        `<testcase classname="pnpm-audit" name="${xmlEscape(name)}"><failure message="blocked">${xmlEscape(msg)}</failure></testcase>`,
      );
      continue;
    }

    if (warned) {
      const msg = relevantDecisions
        .map((d) => `${d.source}: ${d.reason}`)
        .join("\n");
      if (failOnWarn) {
        cases.push(
          `<testcase classname="pnpm-audit" name="${xmlEscape(name)}"><failure message="warning treated as failure">${xmlEscape(msg)}</failure></testcase>`,
        );
      } else {
        cases.push(
          `<testcase classname="pnpm-audit" name="${xmlEscape(name)}"><skipped message="warnings">${xmlEscape(msg)}</skipped></testcase>`,
        );
      }
      continue;
    }

    cases.push(`<testcase classname="pnpm-audit" name="${xmlEscape(name)}" />`);
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="pnpm-audit" tests="${total}" failures="${failures}" skipped="${skipped}">
${cases.join("\n")}
</testsuite>
`;
}
