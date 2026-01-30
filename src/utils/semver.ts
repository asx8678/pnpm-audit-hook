import semver from "semver";

/** Safe semver.satisfies wrapper - returns false if inputs are invalid. */
export function satisfies(version: string, range: string): boolean {
  const v = semver.valid(version);
  if (!v) return false;
  try {
    return semver.satisfies(v, range, { includePrerelease: true });
  } catch (e) {
    console.warn(`[pnpm-audit] Invalid semver range "${range}" for version "${v}":`, e instanceof Error ? e.message : String(e));
    return false;
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
    } else if (ev.fixed !== undefined && intro && gte(v, intro) && lt(v, ev.fixed)) {
      return true;
    } else if (ev.last_affected !== undefined && intro && gte(v, intro) && lte(v, ev.last_affected)) {
      return true;
    }
    if (ev.fixed !== undefined || ev.last_affected !== undefined) intro = null;
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
