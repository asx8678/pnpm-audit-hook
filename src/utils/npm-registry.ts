import type { HttpClient } from "./http";
import type { Cache } from "../cache/memory-cache";

export interface NpmVersionManifest {
  name: string;
  version: string;
  dist?: {
    integrity?: string;
    tarball?: string;
  };
  _npmUser?: { name?: string; email?: string };
  maintainers?: Array<{ name?: string; email?: string }>;
}

/**
 * Fetch the version manifest from the registry. This is a small JSON document and
 * is fetched during resolution anyway; we re-fetch only when needed for integrity checks.
 */
export async function fetchVersionManifest(
  name: string,
  version: string,
  registryUrl: string,
  http: HttpClient,
  cache: Cache,
  ttlSeconds: number,
  offline: boolean,
): Promise<NpmVersionManifest | null> {
  const key = `registry:manifest:${name}@${version}`;
  const cached = await cache.get(key);
  if (cached?.value) return cached.value as NpmVersionManifest;

  if (offline) return null;

  const base = registryUrl.endsWith("/")
    ? registryUrl.slice(0, -1)
    : registryUrl;
  const url = `${base}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
  const json = await http.getJson<any>(url);
  const manifest: NpmVersionManifest = json;
  await cache.set(key, manifest, ttlSeconds);
  return manifest;
}

export function extractDistIntegrity(
  manifest: NpmVersionManifest | null,
): string | undefined {
  return manifest?.dist?.integrity ?? undefined;
}
