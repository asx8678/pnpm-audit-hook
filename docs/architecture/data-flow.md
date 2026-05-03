# Data Flow Documentation

Detailed documentation of data flow through the `pnpm-audit-hook` system.

## Table of Contents

- [Overview](#overview)
- [Primary Audit Flow](#primary-audit-flow)
- [Configuration Flow](#configuration-flow)
- [Vulnerability Source Flow](#vulnerability-source-flow)
- [Static Database Flow](#static-database-flow)
- [Policy Evaluation Flow](#policy-evaluation-flow)
- [Output Generation Flow](#output-generation-flow)
- [Data Transformations](#data-transformations)

---

## Overview

The data flow in `pnpm-audit-hook` follows a pipeline architecture:

```
Input → Validation → Processing → Aggregation → Evaluation → Output
```

Each stage transforms data while maintaining type safety and error boundaries.

---

## Primary Audit Flow

The main audit flow orchestrates all components.

### Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant P as pnpm
    participant H as Hook System
    participant E as Audit Engine
    participant C as Config
    participant X as Extractor
    participant A as Aggregator
    participant S as Sources
    participant Pol as Policy
    participant O as Output

    P->>H: afterAllResolved(lockfile, context)
    Note over H: Extract runtime context
    
    H->>E: runAudit(lockfile, runtime)
    
    rect rgb(255, 243, 224)
        Note over E,C: Configuration Phase
        E->>C: loadConfig(cwd, env)
        C->>C: Find .pnpm-audit.yaml
        C->>C: Parse YAML
        C->>C: Apply env overrides
        C->>C: Validate schema
        C-->>E: AuditConfig
    end
    
    rect rgb(227, 242, 253)
        Note over E,X: Extraction Phase
        E->>X: extractPackagesFromLockfile()
        X->>X: Parse lockfile structure
        X->>X: Filter by config
        X-->>E: PackageRef[]
    end
    
    rect rgb(232, 245, 232)
        Note over E,S: Aggregation Phase
        E->>A: aggregateVulnerabilities()
        
        par Parallel Source Queries
            A->>S: GitHub Advisory
            A->>S: NVD
            A->>S: OSV
            A->>S: Static DB
        end
        
        S-->>A: VulnerabilityFinding[]
        A->>A: Deduplicate findings
        A-->>E: AggregateResult
    end
    
    rect rgb(252, 228, 236)
        Note over E,Pol: Policy Phase
        E->>Pol: evaluatePackagePolicies()
        Pol->>Pol: Check allowlist
        Pol->>Pol: Apply severity rules
        Pol-->>E: PolicyDecision[]
    end
    
    rect rgb(243, 229, 245)
        Note over E,O: Output Phase
        E->>O: outputResults()
        O->>O: Format for CI/CD
        O-->>E: Formatted output
    end
    
    alt Blocked
        E-->>H: AuditResult{blocked: true}
        H-->>P: throw Error(message)
    else Passed
        E-->>H: AuditResult{blocked: false}
        H-->>P: return lockfile
    end
```

### Data Structures at Each Stage

#### Stage 1: Input
```typescript
// From pnpm
interface PnpmLockfile {
  lockfileVersion: string | number;
  packages?: Record<string, LockfilePackageEntry>;
  importers?: Record<string, LockfileImporter>;
}

interface PnpmHookContext {
  lockfileDir?: string;
  storeDir?: string;
  registries?: Record<string, string>;
}
```

#### Stage 2: Configuration
```typescript
interface AuditConfig {
  policy: {
    block: Severity[];
    warn: Severity[];
  };
  sources: {
    github: { enabled: boolean };
    nvd: { enabled: boolean };
    osv: { enabled: boolean };
  };
  performance: {
    timeoutMs: number;
    concurrency: number;
  };
  cache: {
    enabled: boolean;
    ttlSeconds: number;
  };
  allowlist: AllowlistEntry[];
}
```

#### Stage 3: Extracted Packages
```typescript
interface PackageRef {
  name: string;
  version: string;
  registry?: string;
}
```

#### Stage 4: Findings
```typescript
interface VulnerabilityFinding {
  id: string;
  packageName: string;
  packageVersion: string;
  severity: Severity;
  title?: string;
  url?: string;
  fixedVersion?: string;
  identifiers?: VulnerabilityIdentifier[];
  source: FindingSource;
}
```

#### Stage 5: Decisions
```typescript
interface PolicyDecision {
  findingId: string;
  packageName: string;
  packageVersion: string;
  action: PolicyAction;  // 'block' | 'warn' | 'allow'
  reason: string;
  source: DecisionSource;  // 'severity' | 'source' | 'allowlist'
}
```

---

## Configuration Flow

### Mermaid Diagram

```mermaid
flowchart TD
    A[Start] --> B[Get working directory]
    B --> C[Search for .pnpm-audit.yaml]
    
    C --> D{File found?}
    D -->|Yes| E[Read file]
    D -->|No| F[Use default config]
    
    E --> G[Parse YAML]
    G --> H{Parse success?}
    H -->|No| I[Throw ConfigError]
    H -->|Yes| J[Validate schema]
    
    J --> K{Valid?}
    K -->|No| I
    K -->|Yes| L[Load environment variables]
    
    F --> L
    
    L --> M{Env vars exist?}
    M -->|Yes| N[Apply overrides]
    M -->|No| O[Use file config]
    
    N --> P[Merge configs]
    O --> P
    
    P --> Q[Validate final config]
    Q --> R{Valid?}
    R -->|No| I
    R -->|Yes| S[Return AuditConfig]
    
    I --> T[Log error with docs link]
    T --> U[Exit]
    
    style I fill:#ffebee
    style S fill:#e8f5e8
```

### Environment Variable Resolution

```typescript
// Example: policy.block severity override
const envValue = env.PNPM_AUDIT_BLOCK_SEVERITY;
// Input: "critical,high"
// Output: ['critical', 'high']
```

**Resolution Order**:
1. Environment variable (highest priority)
2. YAML file value
3. Built-in default (lowest priority)

---

## Vulnerability Source Flow

### GitHub Advisory Flow

```mermaid
flowchart TD
    A[Package Query] --> B[Check Cache]
    
    B --> C{Cache hit?}
    C -->|Yes| D[Return cached findings]
    C -->|No| E[Check rate limit]
    
    E --> F{Rate limited?}
    F -->|Yes| G[Wait for reset]
    G --> E
    F -->|No| H[Build API query]
    
    H --> I[Query GitHub API]
    I --> J{Response OK?}
    J -->|No| K[Handle error]
    J -->|Yes| L[Parse response]
    
    L --> M[Map to VulnerabilityFinding]
    M --> N[Write to cache]
    N --> D
    
    K --> O{Retryable?}
    O -->|Yes| E
    O -->|No| P[Return error status]
    
    style D fill:#e8f5e8
    style P fill:#ffebee
```

**API Query Construction**:
```graphql
query($ecosystem: String!, $package: String!) {
  securityVulnerabilities(
    ecosystem: $ecosystem
    package: $package
    first: 100
    orderBy: { field: PUBLISHED_AT, direction: DESC }
  ) {
    nodes {
      advisory {
        ghsaId
        cvss { score }
        severity
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
```

### Static Database Flow

```mermaid
flowchart TD
    A[Package Query] --> B{Static DB enabled?}
    
    B -->|No| C[Skip]
    B -->|Yes| D[Load index.json]
    
    D --> E{Package in index?}
    E -->|No| F[Return empty]
    E -->|Yes| G[Get shard path]
    
    G --> H{Shard loaded?}
    H -->|No| I[Lazy load shard]
    H -->|Yes| J[Use cached shard]
    
    I --> K[Read JSON file]
    K --> L[Cache in memory]
    L --> J
    
    J --> M[Filter by cutoff date]
    M --> N[Filter by version]
    
    N --> O[Map to VulnerabilityFinding]
    O --> P[Return findings]
    
    F --> Q[Return empty array]
    P --> Q
    
    style C fill:#e3f2fd
    style F fill:#e3f2fd
    style Q fill:#e8f5e8
```

---

## Policy Evaluation Flow

### Decision Tree

```mermaid
flowchart TD
    A[Findings] --> B{Allowlist enabled?}
    
    B -->|Yes| C[Check allowlist]
    B -->|No| D[Skip allowlist check]
    
    C --> E{Entry matches?}
    E -->|Yes| F{Entry expired?}
    F -->|No| G[Allow - allowlisted]
    F -->|Yes| H[Continue to severity check]
    
    E -->|No| H
    D --> H
    
    H --> I{Severity in block list?}
    I -->|Yes| J[Block]
    I -->|No| K{Severity in warn list?}
    
    K -->|Yes| L[Warn]
    K -->|No| M[Allow - below threshold]
    
    style G fill:#e8f5e8
    style J fill:#ffebee
    style L fill:#fff3e0
    style M fill:#e3f2fd
```

### Allowlist Matching Logic

```typescript
function findAllowlistMatch(
  finding: VulnerabilityFinding,
  allowlist: AllowlistEntry[],
  graph?: DependencyGraph
): AllowlistEntry | undefined {
  
  for (const entry of allowlist) {
    // 1. Check expiration
    if (isExpired(entry)) continue;
    
    // 2. Check direct-only constraint
    if (entry.directOnly && !isDirect(finding, graph)) continue;
    
    // 3. Match by ID and/or package
    const idMatches = entry.id?.toUpperCase() === finding.id.toUpperCase();
    const pkgMatches = entry.package?.toLowerCase() === finding.packageName.toLowerCase();
    
    // 4. Apply version constraint if present
    if (entry.version && !satisfies(finding.packageVersion, entry.version)) {
      continue;
    }
    
    // 5. Return match based on entry type
    if (entry.id && entry.package) {
      if (idMatches && pkgMatches) return entry;
    } else if (entry.id) {
      if (idMatches) return entry;
    } else if (entry.package) {
      if (pkgMatches) return entry;
    }
  }
  
  return undefined;
}
```

---

## Output Generation Flow

### Format Selection

```mermaid
flowchart TD
    A[Output Data] --> B{Explicit format?}
    
    B -->|Yes| C{Use specified format}
    B -->|No| D[Detect from environment]
    
    D --> E{GITHUB_ACTIONS?}
    E -->|Yes| F[GitHub Actions format]
    E -->|No| G{TF_BUILD?}
    
    G -->|Yes| H[Azure DevOps format]
    G -->|No| I{CODEBUILD_BUILD_ID?}
    
    I -->|Yes| J[AWS CodeBuild format]
    I -->|No| K{CI env var?}
    
    K -->|Yes| L[Auto-detect provider]
    K -->|No| M[Human-readable format]
    
    style F fill:#24292e
    style H fill:#0078d7
    style J fill:#ff9900
    style M fill:#e8f5e8
```

### GitHub Actions Output Example

```typescript
function formatGitHubActions(data: AuditOutputData): string {
  const lines: string[] = [];
  
  // Group findings by severity
  for (const finding of data.findings) {
    if (finding.severity === 'critical' || finding.severity === 'high') {
      lines.push(
        `::error file=${finding.packageName}@${finding.packageVersion}` +
        `::${finding.title}`
      );
    } else if (finding.severity === 'medium') {
      lines.push(
        `::warning file=${finding.packageName}@${finding.packageVersion}` +
        `::${finding.title}`
      );
    }
  }
  
  return lines.join('\n');
}
```

---

## Data Transformations

### Lockfile → PackageRef

**Input** (pnpm v9 lockfile):
```yaml
packages:
  /lodash@4.17.21:
    resolution: { integrity: sha512-... }
    dependencies:
      ...
```

**Output**:
```typescript
[
  {
    name: "lodash",
    version: "4.17.21",
    registry: "https://registry.npmjs.org"
  }
]
```

### API Response → VulnerabilityFinding

**GitHub Advisory Response**:
```json
{
  "ghsaId": "GHSA-jf85-cpcp-j695",
  "severity": "HIGH",
  "vulnerabilities": [{
    "package": { "name": "lodash" },
    "vulnerableVersionRange": "< 4.17.21",
    "firstPatchedVersion": { "identifier": "4.17.21" }
  }]
}
```

**Mapped Finding**:
```typescript
{
  id: "GHSA-jf85-cpcp-j695",
  packageName: "lodash",
  packageVersion: "4.17.20",
  severity: "high",
  title: "Prototype Pollution in lodash",
  url: "https://github.com/advisories/GHSA-jf85-cpcp-j695",
  fixedVersion: "4.17.21",
  source: "github"
}
```

### Finding + Policy → Decision

**Finding**:
```typescript
{
  id: "CVE-2021-23337",
  packageName: "lodash",
  severity: "high"
}
```

**Config**:
```typescript
{
  policy: {
    block: ["critical", "high"],
    warn: ["medium"]
  }
}
```

**Decision**:
```typescript
{
  findingId: "CVE-2021-23337",
  packageName: "lodash",
  packageVersion: "4.17.20",
  action: "block",
  reason: "Severity 'high' is in block list",
  source: "severity"
}
```

---

## Performance Considerations

### Parallel Execution

Source queries execute in parallel with these constraints:

```typescript
// Concurrency control
const CONCURRENT_SOURCES = 4;
const SOURCE_TIMEOUT_MS = 15000;

// Parallel execution with Promise.allSettled
const results = await Promise.allSettled([
  githubSource.query(pkgs, ctx),
  nvdSource.query(pkgs, ctx),
  osvSource.query(pkgs, ctx),
  staticDbQuery(pkgs, ctx),
]);
```

### Caching Strategy

```
Cache Key Pattern:
  {source}:{registry}:{package}@{version}:after={cutoff}

Example:
  github:https://registry.npmjs.org:lodash@4.17.21:after=2025-01-01
```

**TTL by Source**:
| Source | Default TTL | Max TTL |
|--------|-------------|---------|
| GitHub | 1 hour | 24 hours |
| NVD | 4 hours | 24 hours |
| OSV | 1 hour | 24 hours |

---

## Error Handling

### Error Boundary Strategy

Each component catches and wraps errors:

```typescript
try {
  const findings = await source.query(pkgs, ctx);
  return { source: source.id, ok: true, findings };
} catch (error) {
  return {
    source: source.id,
    ok: false,
    error: errorMessage(error),
    findings: [],
  };
}
```

### Error Propagation

```
Source Error → AggregateResult.sourceStatus
                ↓
           AuditResult.sourceStatus
                ↓
           Output (shown to user)
                ↓
           Exit code (SOURCE_ERROR = 3)
```

---

## Next Steps

- [Component Details](./components.md)
- [Design Decisions](./decisions.md)
- [Design Patterns](./patterns.md)