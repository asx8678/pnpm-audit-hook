/**
 * EPSS (Exploit Prediction Scoring System) data fetcher.
 *
 * Fetches exploit prediction scores from FIRST.org's EPSS API to provide
 * additional context about vulnerability exploitability. EPSS scores represent
 * the probability that a vulnerability will be exploited in the wild within
 * the next 30 days.
 *
 * @module utils/epss-fetcher
 *
 * @see {@link https://www.first.org/epss/} - EPSS documentation
 * @see {@link https://api.first.org/data/v1/epss} - EPSS API endpoint
 *
 * @example
 * ```typescript
 * import { EpssFetcher } from './epss-fetcher';
 *
 * const fetcher = new EpssFetcher();
 * const epssData = await fetcher.getEpss('CVE-2023-26159');
 * if (epssData) {
 *   console.log(`EPSS Score: ${epssData.epssScore}`);
 *   console.log(`Exploitation probability: ${(epssData.epssScore * 100).toFixed(2)}%`);
 * }
 * ```
 */

import type { EpssData } from "../types";
import { logger } from "./logger";
import { errorMessage } from "./error";

/** EPSS API base URL */
const EPSS_API_BASE = "https://api.first.org/data/v1/epss";

/** Default cache TTL (1 hour in milliseconds) */
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000;

/** Maximum batch size for EPSS API requests */
const MAX_BATCH_SIZE = 200;

/** Rate limit: minimum delay between requests (ms) */
const RATE_LIMIT_DELAY_MS = 100;

/** Default request timeout (ms) */
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Options for configuring the EPSS fetcher.
 */
export interface EpssFetcherOptions {
  /** Custom API base URL (default: https://api.first.org/data/v1/epss) */
  apiUrl?: string;
  /** Cache TTL in milliseconds (default: 1 hour) */
  cacheTtlMs?: number;
  /** Request timeout in milliseconds (default: 10000) */
  timeoutMs?: number;
  /** Enable/disable caching (default: true) */
  enableCache?: boolean;
  /** Enable/disable the fetcher entirely (default: false) */
  disabled?: boolean;
}

/**
 * Cached EPSS data entry with expiration tracking.
 */
interface CacheEntry {
  data: EpssData;
  expiresAt: number;
}

/**
 * Response structure from the EPSS API.
 *
 * @see {@link https://api.first.org/data/v1/epss} - API documentation
 */
interface EpssApiResponse {
  data: Array<{
    cve: string;
    epss: string; // Probability score as string (0.0 - 1.0)
    percentile: string; // Percentile as string (0.0 - 1.0)
    date: string;
  }>;
  meta: {
    apiVersion: string;
    timestamp: string;
  };
}

/**
 * Fetches EPSS (Exploit Prediction Scoring System) data from FIRST.org.
 *
 * Features:
 * - In-memory caching with configurable TTL
 * - Batch fetching for multiple CVEs
 * - Rate limiting to respect API limits
 * - Graceful error handling and fallback
 * - Optional disabled mode for environments without network access
 *
 * @example
 * ```typescript
 * // Basic usage
 * const fetcher = new EpssFetcher();
 * const data = await fetcher.getEpss('CVE-2023-26159');
 *
 * // Batch fetch
 * const epssMap = await fetcher.getEpssBatch(['CVE-2023-26159', 'CVE-2024-1234']);
 *
 * // Custom options
 * const fetcher = new EpssFetcher({
 *   cacheTtlMs: 30 * 60 * 1000, // 30 minutes
 *   timeoutMs: 5000,
 * });
 * ```
 */
export class EpssFetcher {
  private apiUrl: string;
  private cacheTtlMs: number;
  private timeoutMs: number;
  private cache: Map<string, CacheEntry> = new Map();
  private disabled: boolean;
  private lastRequestTime: number = 0;

  constructor(options?: EpssFetcherOptions) {
    this.apiUrl = options?.apiUrl ?? EPSS_API_BASE;
    this.cacheTtlMs = options?.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.disabled = options?.disabled ?? false;
  }

  /**
   * Fetch EPSS data for a single CVE.
   *
   * Returns null if:
   * - The fetcher is disabled
   * - The CVE is not found in the EPSS database
   * - An error occurs during the API request
   *
   * @param cveId - CVE identifier (e.g., "CVE-2023-26159")
   * @returns EPSS data if found, null otherwise
   */
  async getEpss(cveId: string): Promise<EpssData | null> {
    if (this.disabled) {
      return null;
    }

    // Check cache first
    if (this.options.enableCache !== false) {
      const cached = this.getFromCache(cveId);
      if (cached) {
        return cached;
      }
    }

    try {
      const results = await this.fetchBatch([cveId]);
      const data = results.get(cveId) ?? null;

      // Cache the result
      if (data && this.options.enableCache !== false) {
        this.setCache(cveId, data);
      }

      return data;
    } catch (error) {
      logger.debug(`EPSS fetch failed for ${cveId}: ${errorMessage(error)}`);
      return null;
    }
  }

  /**
   * Fetch EPSS data for multiple CVEs in a single batch request.
   *
   * Automatically handles:
   * - Cache lookup for each CVE
   * - Batching requests to stay within API limits
   * - Rate limiting between requests
   *
   * @param cveIds - Array of CVE identifiers
   * @returns Map of CVE ID to EPSS data (only includes found CVEs)
   */
  async getEpssBatch(cveIds: string[]): Promise<Map<string, EpssData>> {
    if (this.disabled || cveIds.length === 0) {
      return new Map();
    }

    const results = new Map<string, EpssData>();
    const uncachedIds: string[] = [];

    // Check cache first
    for (const cveId of cveIds) {
      if (this.options.enableCache !== false) {
        const cached = this.getFromCache(cveId);
        if (cached) {
          results.set(cveId, cached);
          continue;
        }
      }
      uncachedIds.push(cveId);
    }

    if (uncachedIds.length === 0) {
      return results;
    }

    // Fetch in batches
    const batches = this.createBatches(uncachedIds, MAX_BATCH_SIZE);

    for (const batch of batches) {
      try {
        const batchResults = await this.fetchBatch(batch);

        for (const [cveId, data] of batchResults) {
          results.set(cveId, data);
          if (this.options.enableCache !== false) {
            this.setCache(cveId, data);
          }
        }
      } catch (error) {
        logger.debug(`EPSS batch fetch failed: ${errorMessage(error)}`);
        // Continue with other batches on failure
      }

      // Rate limit between batches
      if (batches.length > 1) {
        await this.throttle();
      }
    }

    return results;
  }

  /**
   * Get cache size for monitoring/debugging.
   */
  get cacheSize(): number {
    return this.cache.size;
  }

  /**
   * Clear the in-memory cache.
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get all cached CVE IDs.
   */
  getCachedCveIds(): string[] {
    return Array.from(this.cache.keys());
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /** Access options for internal use */
  private get options(): EpssFetcherOptions {
    return {
      apiUrl: this.apiUrl,
      cacheTtlMs: this.cacheTtlMs,
      timeoutMs: this.timeoutMs,
      enableCache: true,
    };
  }

  /**
   * Fetch a batch of CVEs from the EPSS API.
   */
  private async fetchBatch(cveIds: string[]): Promise<Map<string, EpssData>> {
    await this.throttle();

    const params = new URLSearchParams({
      cve: cveIds.join(","),
    });

    const url = `${this.apiUrl}?${params.toString()}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        headers: {
          Accept: "application/json",
          "User-Agent": "pnpm-audit-hook/1.0.0",
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`EPSS API returned ${response.status}: ${response.statusText}`);
      }

      const data: EpssApiResponse = await response.json() as EpssApiResponse;
      return this.parseResponse(data);
    } finally {
      clearTimeout(timeout);
      this.lastRequestTime = Date.now();
    }
  }

  /**
   * Parse the EPSS API response into our internal format.
   */
  private parseResponse(response: EpssApiResponse): Map<string, EpssData> {
    const results = new Map<string, EpssData>();

    for (const item of response.data ?? []) {
      const cveId = item.cve;
      const score = parseFloat(item.epss);
      const percentile = parseFloat(item.percentile);

      // Validate parsed values
      if (isNaN(score) || isNaN(percentile)) {
        logger.debug(`Invalid EPSS data for ${cveId}: score=${item.epss}, percentile=${item.percentile}`);
        continue;
      }

      results.set(cveId, {
        cveId,
        epssScore: Math.max(0, Math.min(1, score)),
        epssPercentile: Math.max(0, Math.min(1, percentile)),
        date: item.date || response.meta?.timestamp || new Date().toISOString().split("T")[0]!,
        modelVersion: "v2023.03.01", // Default model version
      });
    }

    return results;
  }

  /**
   * Get EPSS data from cache if not expired.
   */
  private getFromCache(cveId: string): EpssData | null {
    const entry = this.cache.get(cveId);
    if (!entry) {
      return null;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(cveId);
      return null;
    }

    return entry.data;
  }

  /**
   * Store EPSS data in cache.
   */
  private setCache(cveId: string, data: EpssData): void {
    this.cache.set(cveId, {
      data,
      expiresAt: Date.now() + this.cacheTtlMs,
    });
  }

  /**
   * Split an array into batches of the given size.
   */
  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  /**
   * Throttle requests to respect rate limits.
   */
  private async throttle(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;

    if (elapsed < RATE_LIMIT_DELAY_MS) {
      await new Promise((resolve) =>
        setTimeout(resolve, RATE_LIMIT_DELAY_MS - elapsed),
      );
    }
  }
}

/**
 * Create an EPSS fetcher with the given options.
 *
 * Factory function for convenient EPSS fetcher creation.
 *
 * @param options - Configuration options
 * @returns Configured EPSS fetcher instance
 */
export function createEpssFetcher(options?: EpssFetcherOptions): EpssFetcher {
  return new EpssFetcher(options);
}

/**
 * Enrich vulnerability findings with EPSS data.
 *
 * Fetches EPSS scores for all CVEs in the findings and attaches the data
 * to each finding. This is a convenience function that handles the mapping
 * between CVE identifiers and findings.
 *
 * @param findings - Array of vulnerability findings to enrich
 * @param fetcher - EPSS fetcher instance (creates default if not provided)
 * @returns Enriched findings with EPSS data attached
 */
export async function enrichFindingsWithEpss(
  findings: import("../types").VulnerabilityFinding[],
  fetcher?: EpssFetcher,
): Promise<import("../types").VulnerabilityFinding[]> {
  const epssFetcher = fetcher ?? new EpssFetcher();

  // Extract all CVE IDs from findings
  const cveIds = new Set<string>();
  for (const finding of findings) {
    // Check identifiers array for CVE IDs
    if (finding.identifiers) {
      for (const id of finding.identifiers) {
        if (id.type === "CVE") {
          cveIds.add(id.value);
        }
      }
    }
    // Also check if the finding ID itself is a CVE
    if (finding.id.startsWith("CVE-")) {
      cveIds.add(finding.id);
    }
  }

  if (cveIds.size === 0) {
    return findings;
  }

  // Fetch EPSS data for all CVEs
  const epssDataMap = await epssFetcher.getEpssBatch(Array.from(cveIds));

  if (epssDataMap.size === 0) {
    return findings;
  }

  // Enrich findings with EPSS data
  return findings.map((finding) => {
    // Try to find EPSS data by matching CVE IDs
    let epssData: EpssData | null = null;

    if (finding.identifiers) {
      for (const id of finding.identifiers) {
        if (id.type === "CVE" && epssDataMap.has(id.value)) {
          epssData = epssDataMap.get(id.value)!;
          break;
        }
      }
    }

    // Also check finding ID directly
    if (!epssData && finding.id.startsWith("CVE-") && epssDataMap.has(finding.id)) {
      epssData = epssDataMap.get(finding.id)!;
    }

    if (epssData) {
      return {
        ...finding,
        epss: epssData,
      };
    }

    return finding;
  });
}
