import fs from "node:fs/promises";
import path from "node:path";
import type { AuditReport, PolicyDecision } from "../types";

export async function writeAuditTrailNdjson(
  report: AuditReport,
  outputDir: string,
  filename = ".pnpm-audit-log.ndjson",
): Promise<string> {
  const p = path.join(outputDir, filename);
  const lines: string[] = [];

  lines.push(
    JSON.stringify({
      type: "summary",
      at: new Date().toISOString(),
      summary: report.summary,
    }),
  );

  for (const d of report.decisions) {
    lines.push(JSON.stringify({ type: "decision", ...d }));
  }

  // Append (preserve history)
  await fs.appendFile(p, lines.join("\n") + "\n", "utf-8");
  return p;
}
