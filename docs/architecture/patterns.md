# Design Patterns Documentation

This document describes the design patterns used in `pnpm-audit-hook`.

## Table of Contents

- [Overview](#overview)
- [Structural Patterns](#structural-patterns)
- [Behavioral Patterns](#behavioral-patterns)
- [Creational Patterns](#creational-patterns)
- [Concurrent Patterns](#concurrent-patterns)
- [Error Handling Patterns](#error-handling-patterns)

---

## Overview

`pnpm-audit-hook` employs several classic and modern design patterns to achieve:
- **Maintainability**: Clear separation of concerns
- **Extensibility**: Easy to add new sources, formatters, policies
- **Testability**: Isolated components with clear interfaces
- **Performance**: Efficient resource utilization

---

## Structural Patterns

### 1. Adapter Pattern

**Used in**: CI/CD Output Formatters

**Purpose**: Convert internal data structures to platform-specific formats.

```typescript
// Internal interface
interface AuditOutputData {
  findings: VulnerabilityFinding[];
  decisions: PolicyDecision[];
  summary: AuditSummary;
}

// Platform adapters
class GitHubActionsFormatter implements OutputFormatter {
  format(data: AuditOutputData): string {
    // Convert to GitHub Actions annotation format
    return data.findings
      .filter(f => f.severity === 'critical' || f.severity === 'high')
      .map(f => `::error file=${f.packageName}::${f.title}`)
      .join('\n');
  }
}

class AzureDevOpsFormatter implements OutputFormatter {
  format(data: AuditOutputData): string {
    // Convert to Azure DevOps logging command format
    return data.findings
      .map(f => `##vso[task.logissue type=error]${f.title}`)
      .join('\n');
  }
}
```

**Benefits**:
- Easy to add new CI/CD platforms
- Internal data structure unchanged
- Platform-specific logic isolated

---

### 2. Strategy Pattern

**Used in**: Vulnerability Sources

**Purpose**: Allow interchangeable algorithms for vulnerability detection.

```typescript
// Strategy interface
interface VulnerabilitySource {
  id: FindingSource;
  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean;
  query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult>;
}

// Concrete strategies
class GitHubAdvisorySource implements VulnerabilitySource {
  id = 'github';
  
  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.github?.enabled !== false;
  }
  
  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    // GitHub-specific implementation
  }
}

class OsvSource implements VulnerabilitySource {
  id = 'osv';
  
  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    // OSV-specific implementation
  }
}

// Context uses strategy
class VulnerabilityAggregator {
  private sources: VulnerabilitySource[];
  
  constructor(sources: VulnerabilitySource[]) {
    this.sources = sources;
  }
  
  async aggregate(pkgs: PackageRef[]): Promise<AggregateResult> {
    const results = await Promise.allSettled(
      this.sources
        .filter(s => s.isEnabled(this.config, this.env))
        .map(s => s.query(pkgs, this.ctx))
    );
    // Process results...
  }
}
```

**Benefits**:
- New sources added without modifying aggregator
- Sources can be enabled/disabled independently
- Easy to test each source in isolation

---

### 3. Decorator Pattern

**Used in**: Cache Layer

**Purpose**: Add caching behavior transparently.

```typescript
// Base interface
interface DataLoader {
  load(key: string): Promise<Data>;
}

// Base implementation
class HttpDataLoader implements DataLoader {
  async load(key: string): Promise<Data> {
    const response = await fetch(key);
    return response.json();
  }
}

// Decorator
class CachingDataLoader implements DataLoader {
  private inner: DataLoader;
  private cache: Map<string, { data: Data; expires: number }>;
  
  constructor(inner: DataLoader) {
    this.inner = inner;
    this.cache = new Map();
  }
  
  async load(key: string): Promise<Data> {
    const cached = this.cache.get(key);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }
    
    const data = await this.inner.load(key);
    this.cache.set(key, {
      data,
      expires: Date.now() + this.ttl,
    });
    
    return data;
  }
}
```

**Benefits**:
- Caching added without modifying base class
- Can stack multiple decorators
- Easy to enable/disable caching

---

### 4. Facade Pattern

**Used in**: Main API (`src/index.ts`)

**Purpose**: Provide a simple interface to a complex subsystem.

```typescript
// Complex subsystem
class AuditEngine {
  private config: ConfigLoader;
  private extractor: PackageExtractor;
  private aggregator: VulnerabilityAggregator;
  private policy: PolicyEngine;
  private formatter: OutputFormatter;
  
  async run(lockfile: PnpmLockfile): Promise<AuditResult> {
    // Complex orchestration...
  }
}

// Facade
export function createPnpmHooks(): PnpmHooks {
  const engine = new AuditEngine();
  
  return {
    hooks: {
      afterAllResolved: async (lockfile, context) => {
        const result = await engine.run(lockfile);
        if (result.blocked) {
          throw new Error(formatErrorMessage(result));
        }
        return lockfile;
      },
    },
  };
}
```

**Benefits**:
- Simple API for consumers
- Internal complexity hidden
- Easy to evolve internals

---

### 5. Composite Pattern

**Used in**: Dependency Graph

**Purpose**: Treat individual objects and compositions uniformly.

```typescript
// Node interface
interface DependencyNode {
  name: string;
  version: string;
  dependencies: DependencyNode[];
}

// Graph as composite
class DependencyGraph {
  private nodes: Map<string, DependencyNode>;
  
  addNode(node: DependencyNode): void {
    this.nodes.set(this.key(node), node);
  }
  
  // Treat entire graph as single unit
  getVulnerablePackages(findings: VulnerabilityFinding[]): DependencyNode[] {
    return Array.from(this.nodes.values())
      .filter(node => this.isVulnerable(node, findings));
  }
  
  // Also treat individual nodes uniformly
  getDependents(node: DependencyNode): DependencyNode[] {
    return this.findDependentsRecursive(node, new Set());
  }
}
```

**Benefits**:
- Uniform treatment of single and composite objects
- Recursive algorithms simplify
- Easy to extend with new node types

---

## Behavioral Patterns

### 6. Observer Pattern

**Used in**: Progress Reporting

**Purpose**: Notify interested parties of state changes.

```typescript
// Subject
class AuditProgress {
  private listeners: Map<string, Array<(data: any) => void>>;
  
  on(event: string, callback: (data: any) => void): void {
    const callbacks = this.listeners.get(event) || [];
    callbacks.push(callback);
    this.listeners.set(event, callbacks);
  }
  
  emit(event: string, data: any): void {
    const callbacks = this.listeners.get(event) || [];
    callbacks.forEach(cb => cb(data));
  }
}

// Usage
const progress = new AuditProgress();

progress.on('source:started', (data) => {
  console.log(`Starting ${data.source}...`);
});

progress.on('source:completed', (data) => {
  console.log(`${data.source} completed in ${data.durationMs}ms`);
});

progress.on('finding', (data) => {
  console.log(`Found vulnerability: ${data.finding.id}`);
});
```

**Benefits**:
- Loose coupling between components
- Easy to add new observers
- Real-time progress updates

---

### 7. Template Method Pattern

**Used in**: Vulnerability Sources

**Purpose**: Define algorithm skeleton, let subclasses override steps.

```typescript
abstract class BaseVulnerabilitySource implements VulnerabilitySource {
  // Template method
  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const startTime = Date.now();
    
    try {
      // Step 1: Check cache
      const cached = await this.checkCache(pkgs, ctx);
      if (cached) return cached;
      
      // Step 2: Build query (abstract)
      const query = this.buildQuery(pkgs, ctx);
      
      // Step 3: Execute query (abstract)
      const response = await this.executeQuery(query, ctx);
      
      // Step 4: Parse response (abstract)
      const findings = this.parseResponse(response);
      
      // Step 5: Update cache
      await this.updateCache(pkgs, findings, ctx);
      
      return {
        source: this.id,
        ok: true,
        findings,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        source: this.id,
        ok: false,
        error: errorMessage(error),
        findings: [],
        durationMs: Date.now() - startTime,
      };
    }
  }
  
  // Abstract methods (implemented by subclasses)
  protected abstract buildQuery(pkgs: PackageRef[], ctx: SourceContext): any;
  protected abstract executeQuery(query: any, ctx: SourceContext): Promise<any>;
  protected abstract parseResponse(response: any): VulnerabilityFinding[];
}
```

**Benefits**:
- Common logic in base class
- Subclasses focus on specifics
- Easy to add new sources

---

### 8. Chain of Responsibility Pattern

**Used in**: Policy Evaluation

**Purpose**: Pass request through a chain of handlers.

```typescript
interface PolicyHandler {
  setNext(handler: PolicyHandler): PolicyHandler;
  handle(finding: VulnerabilityFinding, context: PolicyContext): PolicyDecision | null;
}

// Allowlist handler
class AllowlistHandler implements PolicyHandler {
  private next: PolicyHandler | null = null;
  
  setNext(handler: PolicyHandler): PolicyHandler {
    this.next = handler;
    return handler;
  }
  
  handle(finding: VulnerabilityFinding, context: PolicyContext): PolicyDecision | null {
    const match = context.allowlist.find(e => this.matches(e, finding));
    if (match) {
      return {
        findingId: finding.id,
        action: 'allow',
        source: 'allowlist',
        reason: match.reason || 'Allowlisted',
      };
    }
    return this.next?.handle(finding, context) ?? null;
  }
}

// Severity handler
class SeverityHandler implements PolicyHandler {
  private next: PolicyHandler | null = null;
  
  handle(finding: VulnerabilityFinding, context: PolicyContext): PolicyDecision | null {
    if (context.config.policy.block.includes(finding.severity)) {
      return {
        findingId: finding.id,
        action: 'block',
        source: 'severity',
        reason: `Severity ${finding.severity} is blocked`,
      };
    }
    // Continue chain...
    return this.next?.handle(finding, context) ?? null;
  }
}

// Build chain
const chain = new AllowlistHandler();
chain.setNext(new SeverityHandler())
     .setNext(new WarnHandler())
     .setNext(new DefaultAllowHandler());
```

**Benefits**:
- Dynamic chain configuration
- Easy to add new handlers
- Single responsibility per handler

---

### 9. Command Pattern

**Used in**: CLI Operations

**Purpose**: Encapsulate operations as objects.

```typescript
interface Command {
  execute(): Promise<void>;
  undo?(): Promise<void>;
}

class ScanCommand implements Command {
  constructor(
    private options: ScanOptions,
    private engine: AuditEngine
  ) {}
  
  async execute(): Promise<void> {
    const result = await this.engine.run(this.options.lockfile);
    console.log(this.formatResult(result));
  }
}

class SetupCommand implements Command {
  constructor(private options: SetupOptions) {}
  
  async execute(): Promise<void> {
    await this.createConfigFile();
    await this.createPnpmfile();
  }
  
  async undo(): Promise<void> {
    await this.removeCreatedFiles();
  }
}

// Command registry
const commands: Map<string, CommandFactory> = new Map();
commands.set('scan', (opts) => new ScanCommand(opts, engine));
commands.set('setup', (opts) => new SetupCommand(opts));
```

**Benefits**:
- Operations are first-class objects
- Easy to add undo/redo
- Commands can be serialized/logged

---

## Creational Patterns

### 10. Factory Pattern

**Used in**: Hook Creation

**Purpose**: Create objects without specifying exact class.

```typescript
// Factory function
export function createPnpmHooks(): PnpmHooks {
  // Factory decides which implementation to use
  const config = loadConfigSync();
  
  if (config.offline) {
    return createOfflineHooks();
  }
  
  return createOnlineHooks();
}

function createOnlineHooks(): PnpmHooks {
  return {
    hooks: {
      afterAllResolved: async (lockfile, context) => {
        // Full audit with API calls
        const result = await runAudit(lockfile, {
          cwd: context.lockfileDir,
          env: process.env,
        });
        
        if (result.blocked) {
          throw new Error(buildErrorMessage(result));
        }
        
        return lockfile;
      },
    },
  };
}

function createOfflineHooks(): PnpmHooks {
  return {
    hooks: {
      afterAllResolved: async (lockfile, context) => {
        // Audit using only static DB
        const result = await runOfflineAudit(lockfile);
        // ...
      },
    },
  };
}
```

**Benefits**:
- Client code decoupled from concrete classes
- Easy to switch implementations
- Centralized creation logic

---

### 11. Builder Pattern

**Used in**: Configuration Building

**Purpose**: Construct complex objects step by step.

```typescript
class ConfigBuilder {
  private config: Partial<AuditConfig> = {};
  
  blockSeverities(...severities: Severity[]): this {
    this.config.policy = {
      ...this.config.policy,
      block: severities,
    };
    return this;
  }
  
  warnSeverities(...severities: Severity[]): this {
    this.config.policy = {
      ...this.config.policy,
      warn: severities,
    };
    return this;
  }
  
  allowPackage(name: string, options?: AllowlistOptions): this {
    this.config.allowlist = [
      ...(this.config.allowlist || []),
      { package: name, ...options },
    ];
    return this;
  }
  
  withTimeout(ms: number): this {
    this.config.performance = {
      ...this.config.performance,
      timeoutMs: ms,
    };
    return this;
  }
  
  build(): AuditConfig {
    return {
      policy: { block: ['critical', 'high'], warn: ['medium'], ...this.config.policy },
      sources: { github: { enabled: true }, nvd: { enabled: true }, osv: { enabled: true }, ...this.config.sources },
      performance: { timeoutMs: 15000, concurrency: 4, ...this.config.performance },
      ...this.config,
    } as AuditConfig;
  }
}

// Usage
const config = new ConfigBuilder()
  .blockSeverities('critical', 'high')
  .warnSeverities('medium')
  .allowPackage('lodash', { reason: 'Not exploitable' })
  .withTimeout(30000)
  .build();
```

**Benefits**:
- Readable object construction
- Validation at build time
- Fluent API

---

### 12. Singleton Pattern (Controlled)

**Used in**: Logger

**Purpose**: Ensure single instance with controlled access.

```typescript
// Singleton with injection support
class Logger {
  private static instance: Logger;
  private level: LogLevel;
  
  // For testing: allow injection
  static create(level?: LogLevel): Logger {
    return new Logger(level);
  }
  
  // Default singleton
  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }
  
  private constructor(level?: LogLevel) {
    this.level = level || this.getLevelFromEnv();
  }
  
  private getLevelFromEnv(): LogLevel {
    return (process.env.PNPM_AUDIT_LOG_LEVEL as LogLevel) || 'info';
  }
  
  info(message: string, ...args: any[]): void {
    if (this.shouldLog('info')) {
      console.log(`[INFO] ${message}`, ...args);
    }
  }
  
  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.level);
  }
}

// Usage
const logger = Logger.getInstance();
// or for testing
const testLogger = Logger.create('debug');
```

**Benefits**:
- Single instance globally
- Testable with injection
- Lazy initialization

---

## Concurrent Patterns

### 13. Producer-Consumer Pattern

**Used in**: Parallel Source Queries

**Purpose**: Separate task production from execution.

```typescript
// Producer: creates queries
class QueryProducer {
  private queue: QueryTask[] = [];
  
  enqueue(task: QueryTask): void {
    this.queue.push(task);
  }
  
  dequeue(): QueryTask | undefined {
    return this.queue.shift();
  }
  
  get length(): number {
    return this.queue.length;
  }
}

// Consumer: executes queries
class QueryConsumer {
  private producer: QueryProducer;
  private concurrency: number;
  private running: number = 0;
  
  async process(): Promise<void> {
    while (this.producer.length > 0 || this.running > 0) {
      while (this.running < this.concurrency && this.producer.length > 0) {
        const task = this.producer.dequeue();
        if (task) {
          this.running++;
          this.executeTask(task).finally(() => {
            this.running--;
          });
        }
      }
      await sleep(10);
    }
  }
  
  private async executeTask(task: QueryTask): Promise<void> {
    // Execute with timeout and error handling
  }
}
```

**Benefits**:
- Controlled concurrency
- Load balancing
- Resource management

---

### 14. Circuit Breaker Pattern

**Used in**: HTTP Client

**Purpose**: Prevent cascading failures.

```typescript
class CircuitBreaker {
  private state: 'closed' | 'open' | 'half-open' = 'closed';
  private failureCount: number = 0;
  private lastFailureTime: number = 0;
  
  constructor(
    private failureThreshold: number = 5,
    private resetTimeoutMs: number = 30000
  ) {}
  
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailureTime > this.resetTimeoutMs) {
        this.state = 'half-open';
      } else {
        throw new CircuitOpenError('Circuit breaker is open');
      }
    }
    
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  private onSuccess(): void {
    this.failureCount = 0;
    this.state = 'closed';
  }
  
  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'open';
    }
  }
}

// Usage
const breaker = new CircuitBreaker(3, 60000);

try {
  const data = await breaker.execute(() => fetch(url));
} catch (error) {
  if (error instanceof CircuitOpenError) {
    // Fallback to cache or static DB
  }
}
```

**Benefits**:
- Prevents cascade failures
- Allows system recovery
- Graceful degradation

---

### 15. Throttle/Debounce Pattern

**Used in**: Rate Limiting

**Purpose**: Control execution frequency.

```typescript
class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  
  constructor(
    private maxTokens: number,
    private refillIntervalMs: number
  ) {
    this.tokens = maxTokens;
    this.lastRefill = Date.now();
  }
  
  async acquire(): Promise<void> {
    this.refill();
    
    while (this.tokens <= 0) {
      await sleep(100);
      this.refill();
    }
    
    this.tokens--;
  }
  
  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const tokensToAdd = Math.floor(elapsed / this.refillIntervalMs) * this.maxTokens;
    
    if (tokensToAdd > 0) {
      this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
      this.lastRefill = now;
    }
  }
}

// Usage
const limiter = new RateLimiter(10, 60000); // 10 requests per minute

async function apiCall(url: string): Promise<Response> {
  await limiter.acquire();
  return fetch(url);
}
```

**Benefits**:
- Prevents API rate limit violations
- Smooths request bursts
- Configurable limits

---

## Error Handling Patterns

### 16. Result Pattern

**Used in**: Source Queries

**Purpose**: Return success/failure without exceptions.

```typescript
// Result type
type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

// Usage
async function querySource(
  pkgs: PackageRef[],
  ctx: SourceContext
): Promise<Result<VulnerabilityFinding[], HttpError>> {
  try {
    const findings = await executeQuery(pkgs, ctx);
    return { ok: true, value: findings };
  } catch (error) {
    return { ok: false, error: error as HttpError };
  }
}

// Handling
const result = await querySource(pkgs, ctx);
if (result.ok) {
  console.log(`Found ${result.value.length} vulnerabilities`);
} else {
  console.error(`Query failed: ${result.error.message}`);
}
```

**Benefits**:
- Explicit error handling
- No unexpected exceptions
- Type-safe error handling

---

### 17. Retry Pattern

**Used in**: HTTP Client

**Purpose**: Handle transient failures gracefully.

```typescript
async function withRetry<T>(
  fn: () => Promise<T>,
  options: {
    retries?: number;
    backoffMs?: number;
    shouldRetry?: (error: Error) => boolean;
  } = {}
): Promise<T> {
  const { retries = 3, backoffMs = 250, shouldRetry = () => true } = options;
  
  let lastError: Error | undefined;
  
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      
      if (attempt < retries && shouldRetry(lastError)) {
        const delay = backoffMs * Math.pow(2, attempt);
        await sleep(delay);
      }
    }
  }
  
  throw lastError;
}

// Usage
const data = await withRetry(
  () => fetch(url),
  {
    retries: 3,
    shouldRetry: (err) => err instanceof HttpError && err.status >= 500,
  }
);
```

**Benefits**:
- Handles transient failures
- Exponential backoff prevents thundering herd
- Configurable retry logic

---

## Summary

| Pattern | Category | Location | Purpose |
|---------|----------|----------|---------|
| Adapter | Structural | Formatters | Platform compatibility |
| Strategy | Behavioral | Sources | Interchangeable algorithms |
| Decorator | Structural | Cache | Transparent enhancement |
| Facade | Structural | API | Simplified interface |
| Composite | Structural | Dependency Graph | Uniform treatment |
| Observer | Behavioral | Progress | Event notification |
| Template Method | Behavioral | Sources | Algorithm skeleton |
| Chain of Responsibility | Behavioral | Policy | Request processing |
| Command | Behavioral | CLI | Operation encapsulation |
| Factory | Creational | Hooks | Object creation |
| Builder | Creational | Config | Complex construction |
| Singleton | Creational | Logger | Single instance |
| Producer-Consumer | Concurrent | Parallel Queries | Task processing |
| Circuit Breaker | Concurrent | HTTP Client | Failure prevention |
| Throttle | Concurrent | Rate Limiter | Frequency control |
| Result | Error Handling | Sources | Explicit errors |
| Retry | Error Handling | HTTP Client | Transient failure |

---

## Next Steps

- [Component Details](./components.md)
- [Data Flow](./data-flow.md)
- [Contributor Guide](#contributor-guide)