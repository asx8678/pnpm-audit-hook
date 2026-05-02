/**
 * Shared test utilities for database connector tests.
 *
 * Provides mock factories for Cache, HttpClient, and common config helpers
 * used across osv.test.ts, github-advisory.test.ts, and other connector tests.
 */
import type { AuditConfig, VulnerabilityFinding } from "../../src/types";
import type { Cache, CacheEntry } from "../../src/cache/types";
import type { HttpClient } from "../../src/utils/http";
import type { SourceContext } from "../../src/databases/connector";

const REGISTRY_URL = "https://registry.npmjs.org";

export { REGISTRY_URL };

// ─── Config Helpers ──────────────────────────────────────────────────────────

export function baseConfig(): AuditConfig {
  return {
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
    },
    sources: {
      github: { enabled: true },
      nvd: { enabled: true },
      osv: { enabled: true },
    },
    performance: { timeoutMs: 15000 },
    cache: { ttlSeconds: 3600 },
    failOnNoSources: true,
    failOnSourceError: true,
  };
}

// ─── Cache Mock ──────────────────────────────────────────────────────────────

export function createMockCache(): Cache & { store: Map<string, CacheEntry<unknown>> } {
  const store = new Map<string, CacheEntry<unknown>>();
  return {
    store,
    async get(key: string): Promise<CacheEntry<unknown> | null> {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiresAt < Date.now()) {
        store.delete(key);
        return null;
      }
      return entry;
    },
    async set(key: string, value: unknown, ttlSeconds: number, options?: { version?: string; dependencies?: string[] }): Promise<void> {
      const now = Date.now();
      store.set(key, {
        value,
        storedAt: now,
        expiresAt: now + ttlSeconds * 1000,
        version: options?.version,
        dependencies: options?.dependencies,
      });
    },
    async delete(key: string): Promise<boolean> {
      return store.delete(key);
    },
    async has(key: string): Promise<boolean> {
      return store.has(key);
    },
    async clear(): Promise<void> {
      store.clear();
    },
    getStatistics() {
      return {
        hits: 0,
        misses: 0,
        sets: 0,
        deletes: 0,
        evictions: 0,
        totalEntries: store.size,
        totalSizeBytes: 0,
        averageReadTimeMs: 0,
        averageWriteTimeMs: 0,
        prunedEntries: 0,
      };
    },
    async prune() {
      return { pruned: 0, failed: 0 };
    },
    getHealth() {
      return {
        status: "healthy" as const,
        hitRate: 0,
        sizeBytes: 0,
        entryCount: store.size,
        recommendations: [] as string[],
      };
    },
  };
}

// ─── Finding Builder ─────────────────────────────────────────────────────────

export function finding(overrides: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    id: "CVE-2025-0001",
    source: "github",
    packageName: "test-pkg",
    packageVersion: "1.0.0",
    severity: "high",
    ...overrides,
  };
}

// ─── Context Builder ─────────────────────────────────────────────────────────

export function createContext(
  cache: Cache,
  http: HttpClient,
  cfgOverrides: Partial<AuditConfig> = {},
  env: Record<string, string | undefined> = {},
  registryUrl: string = REGISTRY_URL,
): SourceContext {
  return {
    cfg: { ...baseConfig(), ...cfgOverrides },
    env,
    cache,
    http,
    registryUrl,
  };
}
