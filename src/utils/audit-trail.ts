import fs from "node:fs/promises";
import path from "node:path";
import type { AuditReport } from "../types";

export async function writeAuditTrailNdjson(
  report: AuditReport,
  outputDir: string,
  filename = ".pnpm-audit-log.ndjson",
): Promise<string> {
  const p = path.join(outputDir, filename);
  const lines = [
    JSON.stringify({ type: "summary", at: new Date().toISOString(), summary: report.summary }),
    ...report.decisions.map((d) => JSON.stringify({ type: "decision", ...d })),
  ];
  await fs.appendFile(p, lines.join("\n") + "\n", "utf-8");
  return p;
}
