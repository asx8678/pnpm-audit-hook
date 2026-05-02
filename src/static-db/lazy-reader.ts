import type {
  StaticDbReader,
  StaticDbReaderConfig,
  QueryPerformanceMetrics,
} from "./reader";
import type { StaticDbIndex, StaticDbQueryOptions } from "./types";

import type { VulnerabilityFinding } from "../types";
import { createStaticDbReader } from "./reader";
import { logger } from "../utils/logger";
import { errorMessage } from "../utils/error";

/**
 * Lazy-loading wrapper for StaticDbReader.
 * Defers database initialization until first access, improving startup time.
 * Handles concurrent access properly — multiple calls before initialization
 * completes will all wait for the same initialization promise.
 */
export class LazyStaticDbReader implements StaticDbReader {
  private instance: StaticDbReader | null = null;
  private loadingPromise: Promise<StaticDbReader | null> | null = null;
  private config: StaticDbReaderConfig;
  private initializationError: string | null = null;

  constructor(config: StaticDbReaderConfig) {
    this.config = config;
  }

  /**
   * Get or initialize the underlying StaticDbReader instance.
   * Thread-safe: multiple concurrent calls share the same initialization promise.
   * Returns null if initialization fails.
   */
  async getInstance(): Promise<StaticDbReader | null> {
    // Already initialized — return cached instance
    if (this.instance) {
      return this.instance;
    }

    // Initialization already in progress — wait for it
    if (this.loadingPromise) {
      return this.loadingPromise;
    }

    // Start initialization
    this.loadingPromise = this.initialize();
    return this.loadingPromise;
  }

  private async initialize(): Promise<StaticDbReader | null> {
    try {
      const reader = await createStaticDbReader(this.config);

      if (!reader) {
        this.initializationError = "Static DB initialization returned null";
        logger.warn("LazyStaticDbReader: initialization returned null");
        return null;
      }

      this.instance = reader;
      logger.debug("LazyStaticDbReader: initialized successfully");
      return reader;
    } catch (e) {
      this.initializationError = errorMessage(e);
      logger.error(`LazyStaticDbReader: initialization failed: ${this.initializationError}`);
      return null;
    }
  }

  /**
   * Query vulnerabilities for a specific package.
   * Triggers initialization if not yet done.
   */
  async queryPackage(packageName: string): Promise<VulnerabilityFinding[]> {
    const instance = await this.getInstance();
    if (!instance) return [];
    return instance.queryPackage(packageName);
  }

  /**
   * Query vulnerabilities for a specific package with filtering options.
   * Triggers initialization if not yet done.
   */
  async queryPackageWithOptions(
    packageName: string,
    options?: StaticDbQueryOptions,
  ): Promise<VulnerabilityFinding[]> {
    const instance = await this.getInstance();
    if (!instance) return [];
    return instance.queryPackageWithOptions(packageName, options);
  }

  /**
   * Batch query vulnerabilities for multiple packages.
   * Triggers initialization if not yet done.
   */
  async queryPackagesBatch(
    packageNames: string[],
    options?: StaticDbQueryOptions,
  ): Promise<Map<string, VulnerabilityFinding[]>> {
    const instance = await this.getInstance();
    if (!instance) return new Map();
    return instance.queryPackagesBatch(packageNames, options);
  }

  /**
   * Check if a package has any known vulnerabilities.
   * Triggers initialization if not yet done.
   * Returns false if initialization failed.
   */
  async hasVulnerabilities(packageName: string): Promise<boolean> {
    const instance = await this.getInstance();
    if (!instance) return false;
    return instance.hasVulnerabilities(packageName);
  }

  /**
   * Check if the static database is loaded and ready.
   * Returns false until initialization completes successfully.
   */
  isReady(): boolean {
    return this.instance?.isReady() ?? false;
  }

  /**
   * Get the cutoff date for the static database.
   * Falls back to config cutoff date if not yet initialized.
   */
  getCutoffDate(): string {
    return this.instance?.getCutoffDate() ?? this.config.cutoffDate;
  }

  /**
   * Get the database version identifier.
   * Returns empty string if not yet initialized.
   */
  getDbVersion(): string {
    return this.instance?.getDbVersion() ?? "";
  }

  /**
   * Get the full database index.
   * Returns null if not yet initialized.
   */
  getIndex(): StaticDbIndex | null {
    return this.instance?.getIndex() ?? null;
  }

  /**
   * Get performance metrics for the reader.
   * Returns default metrics if not yet initialized.
   */
  getPerformanceMetrics(): QueryPerformanceMetrics {
    if (this.instance) {
      return this.instance.getPerformanceMetrics();
    }
    return {
      shardCache: { size: 0, maxSize: 0, utilization: 0 },
      queryCache: { size: 0, maxSize: 0, utilization: 0 },
      queryPerformance: {
        queryCount: 0,
        totalDurationMs: 0,
        minDurationMs: 0,
        maxDurationMs: 0,
        avgDurationMs: 0,
        p50DurationMs: 0,
        p95DurationMs: 0,
        p99DurationMs: 0,
        cacheHits: 0,
        cacheMisses: 0,
        cacheHitRate: 0,
      },
    };
  }

  /**
   * Check if initialization has failed.
   */
  hasInitializationError(): boolean {
    return this.initializationError !== null;
  }

  /**
   * Get the initialization error message, if any.
   */
  getInitializationError(): string | null {
    return this.initializationError;
  }

  /**
   * Reset the reader, clearing cached state and allowing re-initialization.
   * Useful for testing or when the underlying database is updated.
   */
  reset(): void {
    this.instance = null;
    this.loadingPromise = null;
    this.initializationError = null;
  }
}
