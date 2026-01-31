import semver from "semver";
import { logger } from "./logger";
import { errorMessage } from "./error";

/** Safe semver.satisfies wrapper - returns true on invalid ranges (fail-closed for security). */
export function satisfies(version: string, range: string): boolean {
  const v = semver.valid(version);
  if (!v) return false;

  // Normalize GitHub Advisory's comma-separated ranges to space-separated
  // GitHub returns: ">= 1.0.0, < 1.2.6" but semver expects ">=1.0.0 <1.2.6"
  const normalizedRange = range.replace(/,\s*/g, ' ');

  try {
    return semver.satisfies(v, normalizedRange, { includePrerelease: true });
  } catch (e) {
    logger.warn(`Invalid semver range "${range}" for version "${v}", treating as potentially affected (fail-closed): ${errorMessage(e)}`);
    return true; // Fail-closed for security
  }
}

const cmp = (fn: typeof semver.lt) => (a: string, b: string) =>
  !!(semver.valid(a) && semver.valid(b) && fn(a, b));

const lt = cmp(semver.lt), lte = cmp(semver.lte), gte = cmp(semver.gte);

/** OSV affected range evaluation (SEMVER type). Returns true if version is within any [introduced, fixed) interval. */
export function isVersionAffectedByOsvSemverRange(
  version: string,
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>,
): boolean {
  const v = semver.valid(version);
  if (!v) return false;

  const normalize = (s: string) => (s === "0" ? "0.0.0" : s);
  let intro: string | null = null;

  for (const ev of events) {
    if (ev.introduced !== undefined) {
      intro = normalize(ev.introduced);
    }
    if (ev.fixed !== undefined && intro && gte(v, intro) && lt(v, ev.fixed)) {
      return true;
    }
    if (ev.last_affected !== undefined && intro && gte(v, intro) && lte(v, ev.last_affected)) {
      return true;
    }
    if (ev.fixed !== undefined || ev.last_affected !== undefined) {
      intro = null;
    }
  }

  return intro !== null && gte(v, intro);
}

/** Builds a best-effort purl for npm packages. */
export function npmPurl(name: string, version?: string): string {
  const suffix = version ? `@${encodeURIComponent(version)}` : "";
  if (name.startsWith("@")) {
    const [scope, pkg = ""] = name.split("/");
    return `pkg:npm/${encodeURIComponent(scope!)}/${encodeURIComponent(pkg)}${suffix}`;
  }
  return `pkg:npm/${encodeURIComponent(name)}${suffix}`;
}
