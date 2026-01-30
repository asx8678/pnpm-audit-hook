import semver from "semver";

/**
 * Safe semver.satisfies wrapper.
 * - Returns false if inputs are invalid
 */
export function satisfies(version: string, range: string): boolean {
  const v = semver.valid(version);
  if (!v) return false;
  try {
    return semver.satisfies(v, range, { includePrerelease: true });
  } catch (e) {
    // Log invalid ranges - could cause vulnerabilities to be missed
    console.warn(
      `[pnpm-audit] Invalid semver range "${range}" for version "${v}":`,
      e instanceof Error ? e.message : String(e),
    );
    return false;
  }
}

export function lt(a: string, b: string): boolean {
  const va = semver.valid(a);
  const vb = semver.valid(b);
  if (!va || !vb) return false;
  return semver.lt(va, vb);
}

export function lte(a: string, b: string): boolean {
  const va = semver.valid(a);
  const vb = semver.valid(b);
  if (!va || !vb) return false;
  return semver.lte(va, vb);
}

export function gte(a: string, b: string): boolean {
  const va = semver.valid(a);
  const vb = semver.valid(b);
  if (!va || !vb) return false;
  return semver.gte(va, vb);
}

export function valid(version: string): boolean {
  return Boolean(semver.valid(version));
}

/**
 * OSV affected range evaluation (SEMVER type).
 *
 * OSV records represent a set of half-open intervals via a sequence of events:
 *   introduced: X
 *   fixed: Y
 * Means versions >=X and <Y are affected.
 *
 * Multiple introduced/fixed sequences can appear.
 */
export function isVersionAffectedByOsvSemverRange(
  version: string,
  events: Array<{
    introduced?: string;
    fixed?: string;
    last_affected?: string;
  }>,
): boolean {
  const v = semver.valid(version);
  if (!v) return false;

  // Track current introduced point (inclusive).
  let currentIntroduced: string | null = null;

  for (const ev of events) {
    if (ev.introduced !== undefined) {
      currentIntroduced = ev.introduced === "0" ? "0.0.0" : ev.introduced;
      continue;
    }

    // "fixed" closes the interval: [introduced, fixed)
    if (ev.fixed !== undefined) {
      if (currentIntroduced === null) continue;
      const intro = currentIntroduced === "0" ? "0.0.0" : currentIntroduced;
      if (gte(v, intro) && lt(v, ev.fixed)) return true;
      currentIntroduced = null;
      continue;
    }

    // "last_affected" closes the interval inclusive: [introduced, last_affected]
    if (ev.last_affected !== undefined) {
      if (currentIntroduced === null) continue;
      const intro = currentIntroduced === "0" ? "0.0.0" : currentIntroduced;
      if (gte(v, intro) && lte(v, ev.last_affected)) return true;
      currentIntroduced = null;
      continue;
    }
  }

  // If range is still open-ended, then introduced -> infinity.
  if (currentIntroduced !== null) {
    const intro = currentIntroduced === "0" ? "0.0.0" : currentIntroduced;
    if (gte(v, intro)) return true;
  }

  return false;
}

/** Builds a best-effort purl for npm packages. */
export function npmPurl(name: string, version?: string): string {
  // purl format: pkg:npm/%40scope/name@1.2.3 (for scoped)
  if (name.startsWith("@")) {
    const parts = name.split("/");
    const scope = parts[0]!;
    const pkg = parts[1] ?? "";
    const scopeEnc = encodeURIComponent(scope); // encodes @ -> %40
    const pkgEnc = encodeURIComponent(pkg ?? "");
    return `pkg:npm/${scopeEnc}/${pkgEnc}${version ? "@" + encodeURIComponent(version) : ""}`;
  }
  return `pkg:npm/${encodeURIComponent(name)}${version ? "@" + encodeURIComponent(version) : ""}`;
}
