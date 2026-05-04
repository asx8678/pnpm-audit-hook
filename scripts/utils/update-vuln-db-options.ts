/**
 * CLI option helpers for scripts/update-vuln-db.ts.
 * Kept separate so the builder stays focused on data collection/writing.
 */

import type { GitHubAdvisory } from "./update-vuln-db-helpers";

export function getCliOptionValue(args: string[], optionName: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === optionName) {
      return args[i + 1] ?? "";
    }
    if (arg?.startsWith(`${optionName}=`)) {
      return arg.slice(optionName.length + 1);
    }
  }
  return undefined;
}

function getCliOptionValues(args: string[], optionName: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === optionName) {
      values.push(args[i + 1] ?? "");
      i++;
    } else if (arg?.startsWith(`${optionName}=`)) {
      values.push(arg.slice(optionName.length + 1));
    }
  }
  return values;
}

export function parseRetentionYears(args: string[]): number | undefined {
  const values = getCliOptionValues(args, "--years");
  if (values.length === 0) return undefined;
  if (values.length > 1) {
    throw new Error("--years may only be provided once.");
  }

  const raw = values[0]?.trim() ?? "";
  const years = Number(raw);
  if (!raw || !Number.isSafeInteger(years) || years <= 0) {
    throw new Error(`Invalid --years value "${raw}". Expected a positive integer.`);
  }

  return years;
}

export function assertValidIsoDate(value: string, label: string): void {
  if (Number.isNaN(Date.parse(value))) {
    throw new Error(`Invalid ${label} "${value}". Expected an ISO date string.`);
  }
}

export function calculateRetentionSinceDate(cutoffDate: string, years: number): string {
  assertValidIsoDate(cutoffDate, "--cutoff date");
  const cutoff = new Date(cutoffDate);
  const since = new Date(cutoff.getTime());
  since.setUTCFullYear(since.getUTCFullYear() - years);
  return since.toISOString();
}

function dateIsOnOrAfter(value: string | undefined, sinceDate: string): boolean {
  if (!value) return false;
  const time = Date.parse(value);
  return !Number.isNaN(time) && time >= Date.parse(sinceDate);
}

export function advisoryMatchesSince(
  advisory: GitHubAdvisory,
  sinceDate?: string,
): boolean {
  if (!sinceDate) return true;
  return (
    dateIsOnOrAfter(advisory.publishedAt, sinceDate) ||
    dateIsOnOrAfter(advisory.updatedAt, sinceDate)
  );
}
