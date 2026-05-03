# pnpm-audit-hook Architecture

Welcome to the architecture documentation for `pnpm-audit-hook`! 🐶

This document provides a high-level overview of the system, designed to help new contributors understand the codebase and make informed design decisions.

## Table of Contents

- [System Overview](#system-overview)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Design Decisions](#design-decisions)
- [Design Patterns](#design-patterns)
- [Contributor Guide](#contributor-guide)

## System Overview

`pnpm-audit-hook` is a security tool that intercepts pnpm's package installation process to audit dependencies for known vulnerabilities. It acts as a pre-download security gate, blocking vulnerable packages before they are installed.

### Key Features

1. **Multi-Source Aggregation**: Queries GitHub Advisory Database, NVD, and OSV
2. **Offline Support**: Includes a static vulnerability database for air-gapped environments
3. **Policy Engine**: Configurable blocking/warning rules based on severity
4. **Performance Optimized**: Lazy loading, caching, and concurrency controls
5. **CI/CD Ready**: Native output formats for GitHub Actions, Azure DevOps, and AWS CodeBuild

### System Architecture Diagram

```mermaid
graph TB
    subgraph "pnpm Integration"
        A[.pnpmfile.cjs] --> B[createPnpmHooks]
        B --> C[afterAllResolved Hook]
    end

    subgraph "Audit Engine"
        C --> D[runAudit]
        D --> E[Config Loader]
        D --> F[Package Extractor]
        D --> G[Vulnerability Aggregator]
        D --> H[Policy Engine]
        D --> I[Output Formatter]
    end

    subgraph "Vulnerability Sources"
        G --> J[GitHub Advisory API]
        G --> K[NVD API]
        G --> L[OSV API]
        G --> M[Static DB]
    end

    subgraph "Utilities"
        D --> N[HTTP Client]
        D --> O[Cache]
        D --> P[Logger]
        D --> Q[Security Utils]
    end

    style A fill:#e1f5fe
    style B fill:#e1f5fe
    style C fill:#e1f5fe
    style D fill:#f3e5f5
    style E fill:#f3e5f5
    style F fill:#f3e5f5
    style G fill:#f3e5f5
    style H fill:#f3e5f5
    style I fill:#f3e5f5
    style J fill:#e8f5e8
    style K fill:#e8f5e8
    style L fill:#e8f5e8
    style M fill:#e8f5e8
    style N fill:#fff3e0
    style O fill:#fff3e0
    style P fill:#fff3e0
    style Q fill:#fff3e0
```

## Core Components

### 1. Hook System (`src/index.ts`)

The entry point that integrates with pnpm's lifecycle hooks:

```typescript
export function createPnpmHooks(): PnpmHooks {
  return {
    hooks: {
      afterAllResolved: async (lockfile, context) => {
        // Run audit, throw if blocked
        return lockfile;
      },
    },
  };
}
```

**Responsibilities:**
- Create pnpm-compatible hooks object
- Extract runtime context (cwd, env, registry)
- Throw descriptive errors when blocking

### 2. Audit Engine (`src/audit.ts`)

Orchestrates the entire audit process:

```typescript
export async function runAudit(
  lockfile: PnpmLockfile,
  runtime: RuntimeOptions
): Promise<AuditResult>
```

**Responsibilities:**
- Load and validate configuration
- Extract packages from lockfile
- Aggregate vulnerabilities from multiple sources
- Apply policy rules
- Format and output results

### 3. Configuration (`src/config.ts`)

Handles YAML configuration loading with environment variable overrides:

```typescript
export async function loadConfig(opts: ConfigLoadOptions): Promise<AuditConfig>
```

**Features:**
- YAML file parsing with syntax validation
- Environment variable overrides (e.g., `PNPM_AUDIT_BLOCK_SEVERITY`)
- Allowlist with expiration dates
- Typo detection with suggestions
- Path traversal protection

### 4. Package Extractor (`src/utils/lockfile/`)

Extracts package information from pnpm lockfiles:

```typescript
export function extractPackagesFromLockfile(
  lockfile: PnpmLockfile,
  config: AuditConfig
): PackageRef[]
```

**Features:**
- Supports pnpm lockfile v6, v8, v9 formats
- Workspace package handling
- Dev dependency filtering
- Parse caching for performance

### 5. Vulnerability Aggregator (`src/databases/`)

Coordinates queries to multiple vulnerability sources:

```typescript
export async function aggregateVulnerabilities(
  pkgs: PackageRef[],
  ctx: AggregateContext
): Promise<AggregateResult>
```

**Sources:**
| Source | API | Rate Limits | Offline Support |
|--------|-----|-------------|-----------------|
| GitHub Advisory | REST v4 | 100/min (authenticated) | ✅ Static DB |
| NVD | REST 2.0 | 5 req/30s | ❌ |
| OSV | REST v1 | Unlimited | ❌ |
| Static DB | Local JSON | Unlimited | ✅ |

### 6. Policy Engine (`src/policies/policy-engine.ts`)

Evaluates vulnerability findings against configured policies:

```typescript
export function evaluatePackagePolicies(
  findings: VulnerabilityFinding[],
  config: AuditConfig,
  graph?: DependencyGraph
): PolicyDecision[]
```

**Policy Rules:**
- **Severity-based**: Block/warn/allow by severity level
- **Allowlist**: Package or CVE-specific exceptions
- **Direct-only**: Allowlist entries that only apply to direct dependencies
- **Expiration**: Time-based allowlist entry expiration

### 7. Output Formatter (`src/utils/output-formatter.ts`)

Formats audit results for different environments:

```typescript
export function outputResults(
  data: AuditOutputData,
  format?: OutputFormat
): string
```

**Formats:**
- **Human-readable**: Color-coded terminal output
- **GitHub Actions**: `::error` and `::warning` annotations
- **Azure DevOps**: `##vso[task.logissue]` commands
- **AWS CodeBuild**: CloudWatch-compatible format
- **JSON**: Machine-readable for CI pipelines

## Data Flow

### 1. Installation Audit Flow

```mermaid
sequenceDiagram
    participant P as pnpm
    participant H as Hook
    participant A as Audit Engine
    participant C as Config
    participant E as Extractor
    participant V as Vulnerability Sources
    participant P2 as Policy Engine
    participant O as Output Formatter

    P->>H: afterAllResolved(lockfile, context)
    H->>A: runAudit(lockfile, runtime)
    A->>C: loadConfig(cwd, env)
    C-->>A: AuditConfig
    
    A->>E: extractPackagesFromLockfile(lockfile, config)
    E-->>A: PackageRef[]
    
    A->>V: aggregateVulnerabilities(pkgs, ctx)
    par GitHub Advisory
        V->>V: queryGitHubAdvisory()
    and NVD
        V->>V: queryNVD()
    and OSV
        V->>V: queryOSV()
    and Static DB
        V->>V: queryStaticDb()
    end
    V-->>A: VulnerabilityFinding[]
    
    A->>P2: evaluatePackagePolicies(findings, config)
    P2-->>A: PolicyDecision[]
    
    A->>O: outputResults(data, format)
    O-->>A: formatted output
    
    alt Blocked
        A-->>H: AuditResult{blocked: true}
        H-->>P: throw Error
    else Passed
        A-->>H: AuditResult{blocked: false}
        H-->>P: return lockfile
    end
```

### 2. Static Database Query Flow

```mermaid
graph TD
    A[Package Query] --> B{Index Lookup}
    B -->|Found| C[Load Shard File]
    B -->|Not Found| D[Return Empty]
    
    C --> E{Lazy Load?}
    E -->|Yes| F[Load JSON on demand]
    E -->|No| G[Use pre-loaded data]
    
    F --> H[Filter by cutoff date]
    G --> H
    
    H --> I[Convert to VulnerabilityFinding]
    I --> J[Return findings]
    
    style A fill:#e3f2fd
    style B fill:#fff3e0
    style C fill:#e8f5e8
    style D fill:#ffebee
    style F fill:#f3e5f5
    style G fill:#f3e5f5
```

### 3. Configuration Loading Flow

```mermaid
graph TD
    A[Start] --> B[Find .pnpm-audit.yaml]
    B --> C{File exists?}
    C -->|Yes| D[Parse YAML]
    C -->|No| E[Use defaults]
    
    D --> F{Syntax valid?}
    F -->|No| G[Throw ConfigError]
    F -->|Yes| H[Validate schema]
    
    H --> I[Apply env overrides]
    I --> J[Validate values]
    
    J --> K{Valid?}
    K -->|No| G
    K -->|Yes| L[Return AuditConfig]
    
    E --> I
    
    style A fill:#e3f2fd
    style G fill:#ffebee
    style L fill:#e8f5e8
```

## Design Decisions

See [decisions.md](./decisions.md) for detailed Architecture Decision Records (ADRs).

### Key Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Configuration format | YAML | Human-readable, supports comments |
| Static DB format | Sharded JSON | O(1) lookup, minimal memory |
| HTTP client | Native `http/https` | Zero dependencies, connection pooling |
| Type system | TypeScript | Type safety, better DX |
| Testing | Node test runner | Built-in, no extra dependencies |
| Output formats | Multiple CI providers | Maximize compatibility |

## Design Patterns

See [patterns.md](./patterns.md) for detailed pattern documentation.

### Key Patterns Used

1. **Strategy Pattern**: Vulnerability sources (GitHub, NVD, OSV, Static)
2. **Adapter Pattern**: CI/CD output formatters
3. **Decorator Pattern**: Cache wrapping HTTP client
4. **Observer Pattern**: Progress reporting during audit
5. **Factory Pattern**: Hook creation via `createPnpmHooks()`

## Directory Structure

```
pnpm-audit-hook/
├── src/
│   ├── index.ts              # Entry point, hook creation
│   ├── audit.ts              # Core audit orchestration
│   ├── config.ts             # Configuration loading
│   ├── types.ts              # TypeScript definitions
│   ├── databases/            # Vulnerability sources
│   │   ├── connector.ts      # Source interface
│   │   ├── aggregator.ts     # Multi-source coordination
│   │   ├── github-advisory.ts
│   │   ├── nvd.ts
│   │   ├── osv.ts
│   │   └── static-db/        # Offline vulnerability DB
│   ├── policies/
│   │   └── policy-engine.ts  # Policy evaluation
│   ├── cache/                # Caching layer
│   ├── utils/                # Shared utilities
│   │   ├── http.ts           # HTTP client with pooling
│   │   ├── lockfile/         # Lockfile parsing
│   │   ├── output-formatter.ts
│   │   ├── security.ts       # Security utilities
│   │   └── helpers/          # Common helpers
│   └── cli/                  # CLI entry points
├── bin/                      # Executable scripts
├── test/                     # Test suite
├── scripts/                  # Build scripts
└── docs/                     # Documentation
```

## Performance Characteristics

| Operation | Time Complexity | Space Complexity |
|-----------|-----------------|------------------|
| Package extraction | O(n) | O(n) |
| Static DB lookup | O(1) | O(1) per query |
| Dependency graph build | O(V + E) | O(V + E) |
| Policy evaluation | O(f × p) | O(f) |
| Finding deduplication | O(f) | O(f) |

Where: n = packages, V = vertices, E = edges, f = findings, p = policies

## Security Considerations

1. **Input Validation**: All external data is validated before use
2. **Path Traversal Protection**: Config paths are sanitized
3. **Rate Limiting**: API calls are throttled to prevent abuse
4. **Fail-Closed**: Invalid configs/entries are rejected by default
5. **No Eval**: Dynamic code execution is avoided

## Next Steps

- [Components Deep Dive](./components.md)
- [Data Flow Details](./data-flow.md)
- [Design Decisions](./decisions.md)
- [Design Patterns](./patterns.md)
- [Contributor Guide](#contributor-guide)