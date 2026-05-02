/**
 * Rate limiting utilities for API calls.
 * 
 * Implements Token Bucket algorithm and header-based rate limit tracking.
 */

/**
 * Configuration for the rate limiter.
 */
export interface RateLimiterOptions {
  /** Maximum number of requests per interval (token bucket capacity) */
  maxRequests: number;
  /** Interval in milliseconds for token refill */
  intervalMs: number;
  /** Optional: Name of the resource/API for logging */
  name?: string;
  /** Circuit breaker threshold: number of consecutive failures before opening */
  circuitBreakerThreshold?: number;
}

/**
 * Metrics for rate limiter monitoring.
 */
export interface RateLimitMetrics {
  totalRequests: number;
  totalWaited: number;
  totalWaitedMs: number;
  rateLimitedRequests: number;
  circuitBreakerTrips: number;
  currentRemaining: number | null;
}

/**
 * Tracks rate limit state from response headers.
 */
export interface RateLimitState {
  /** Number of requests remaining */
  remaining: number;
  /** Unix timestamp when the limit resets */
  resetTimeMs: number;
  /** Total requests allowed per interval */
  limit: number;
  /** Timestamp when this state was recorded */
  timestampMs: number;
}

/**
 * Token bucket rate limiter implementation.
 * Allows controlled burst capacity while maintaining long-term rate limits.
 */
export class TokenBucket {
  private readonly capacity: number;
  private readonly refillRate: number; // tokens per ms
  private tokens: number;
  private lastRefillTime: number;

  constructor(options: RateLimiterOptions) {
    this.capacity = options.maxRequests;
    this.tokens = options.maxRequests;
    this.refillRate = options.maxRequests / options.intervalMs;
    this.lastRefillTime = Date.now();
  }

  /**
   * Try to consume a token.
   * Returns true if the request can proceed, false if it should wait.
   */
  tryConsume(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /**
   * Get the time (in ms) until a token becomes available.
   * Returns 0 if tokens are currently available.
   */
  getWaitTimeMs(): number {
    this.refill();
    if (this.tokens >= 1) {
      return 0;
    }
    // Calculate how long until we have 1 token
    const deficit = 1 - this.tokens;
    return Math.ceil(deficit / this.refillRate);
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefillTime;
    const newTokens = elapsed * this.refillRate;
    this.tokens = Math.min(this.capacity, this.tokens + newTokens);
    this.lastRefillTime = now;
  }
}

/**
 * Adaptive rate limiter that adjusts based on server-provided headers.
 * Combines local token bucket with server-side feedback and circuit breaker.
 */
export class AdaptiveRateLimiter {
  private readonly localBucket: TokenBucket;
  private readonly name: string;
  private readonly circuitBreakerThreshold: number;
  private serverState: RateLimitState | null = null;
  private consecutiveRateLimits: number = 0;
  private consecutiveFailures: number = 0;
  private circuitOpen: boolean = false;
  private circuitOpenUntil: number = 0;
  
  // Monitoring metrics
  private metrics: RateLimitMetrics = {
    totalRequests: 0,
    totalWaited: 0,
    totalWaitedMs: 0,
    rateLimitedRequests: 0,
    circuitBreakerTrips: 0,
    currentRemaining: null,
  };

  constructor(options: RateLimiterOptions) {
    this.localBucket = new TokenBucket(options);
    this.name = options.name ?? "API";
    this.circuitBreakerThreshold = options.circuitBreakerThreshold ?? 5;
  }

  /**
   * Check if a request should be allowed.
   * Returns wait time in ms (0 if request can proceed immediately).
   */
  async waitIfNeeded(): Promise<number> {
    this.metrics.totalRequests++;
    
    // Check circuit breaker
    if (this.circuitOpen && Date.now() < this.circuitOpenUntil) {
      const remainingMs = this.circuitOpenUntil - Date.now();
      console.warn(`[${this.name}] Circuit is OPEN, waiting ${remainingMs}ms`);
      this.metrics.totalWaited++;
      this.metrics.totalWaitedMs += remainingMs;
      return remainingMs;
    } else if (this.circuitOpen) {
      // Half-open: allow one request to test
      this.circuitOpen = false;
      console.log(`[${this.name}] Circuit half-open, allowing test request`);
    }

    // Check server-side rate limit first
    if (this.serverState) {
      const now = Date.now();
      if (this.serverState.remaining <= 0 && now < this.serverState.resetTimeMs) {
        const waitTime = this.serverState.resetTimeMs - now;
        console.log(`[${this.name}] Server rate limit hit, waiting ${waitTime}ms`);
        this.metrics.rateLimitedRequests++;
        this.metrics.totalWaited++;
        this.metrics.totalWaitedMs += waitTime;
        return waitTime;
      }
    }

    // Check local token bucket
    const localWait = this.localBucket.getWaitTimeMs();
    if (localWait > 0) {
      console.log(`[${this.name}] Local rate limit, waiting ${localWait}ms`);
      this.metrics.rateLimitedRequests++;
      this.metrics.totalWaited++;
      this.metrics.totalWaitedMs += localWait;
      return localWait;
    }

    return 0;
  }

  /**
   * Record rate limit information from response headers.
   */
  updateFromHeaders(headers: Headers): void {
    const remaining = headers.get("x-ratelimit-remaining");
    const limit = headers.get("x-ratelimit-limit");
    const reset = headers.get("x-ratelimit-reset");

    if (remaining !== null && limit !== null && reset !== null) {
      const now = Date.now();
      const resetTimeMs = parseInt(reset, 10) * 1000;
      
      this.serverState = {
        remaining: parseInt(remaining, 10),
        limit: parseInt(limit, 10),
        resetTimeMs,
        timestampMs: now,
      };
      this.metrics.currentRemaining = this.serverState.remaining;
    }
  }

  /**
   * Handle a rate limit response (429).
   * Increases backoff for subsequent requests.
   */
  onRateLimit(): void {
    this.consecutiveRateLimits++;
    console.warn(`[${this.name}] Rate limit exceeded. Consecutive: ${this.consecutiveRateLimits}`);
    
    // Track as failure for circuit breaker
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= this.circuitBreakerThreshold) {
      this.tripCircuitBreaker();
    }
  }

  /**
   * Handle request failure (non-rate-limit errors).
   */
  onFailure(): void {
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= this.circuitBreakerThreshold) {
      this.tripCircuitBreaker();
    }
  }

  /**
   * Reset rate limit state after successful requests.
   */
  onSuccess(): void {
    if (this.consecutiveRateLimits > 0) {
      this.consecutiveRateLimits--;
    }
    this.consecutiveFailures = 0;
  }

  private tripCircuitBreaker(): void {
    this.circuitOpen = true;
    this.circuitOpenUntil = Date.now() + 60000; // Open for 60s
    this.metrics.circuitBreakerTrips++;
    console.error(`[${this.name}] Circuit breaker TRIPPED! Open for 60s`);
  }

  /**
   * Get current state for monitoring.
   */
  getState(): { server: RateLimitState | null; consecutiveRateLimits: number; circuitOpen: boolean } {
    return {
      server: this.serverState,
      consecutiveRateLimits: this.consecutiveRateLimits,
      circuitOpen: this.circuitOpen,
    };
  }

  /**
   * Get metrics for monitoring.
   */
  getMetrics(): RateLimitMetrics {
    return { ...this.metrics };
  }
}
