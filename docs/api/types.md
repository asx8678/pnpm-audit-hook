# Type Definitions

> Complete TypeScript type reference for pnpm-audit-hook.

## Table of Contents

- [Core Types](#core-types)
- [Lockfile Types](#lockfile-types)
- [Vulnerability Types](#vulnerability-types)
- [Policy Types](#policy-types)
- [Configuration Types](#configuration-types)
- [Dependency Graph Types](#dependency-graph-types)
- [Risk Assessment Types](#risk-assessment-types)

---

## Core Types

### `Severity`

Vulnerability severity level.

```typescript
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
```

| Value | Description |
|-------|-------------|
| `critical` | Exploitable vulnerability with severe impact |
| `high` | Exploitable vulnerability with significant impact |
| `medium` | Vulnerability with moderate impact or limited exploitability |
| `low` | Vulnerability with minimal impact |
| `unknown` | Severity could not be determined |

---

### `FindingSource`

Source of vulnerability information.

```typescript
type FindingSource = 'github' | 'nvd' | 'osv';
```

| Value | Description |
|-------|-------------|
| `github` | GitHub Advisory Database (GHSA) |
| `nvd` | National Vulnerability Database (NVD) |
| `osv` | Open Source Vulnerabilities (OSV.dev) |

---

### `PolicyAction`

Action taken for a vulnerability finding.

```typescript
type PolicyAction = 'allow' | 'warn' | 'block';
```

| Value | Description |
|-------|-------------|
| `allow` | Vulnerability is permitted (allowlisted) |
| `warn` | Warning displayed but installation continues |
| `block` | Installation is blocked |

---

### `DecisionSource`

Source of the policy decision.

```typescript
type DecisionSource = 'severity' | 'source' | 'allowlist';
```

| Value | Description |
|-------|-------------|
| `severity` | Decision based on severity policy |
| `source` | Decision based on source status |
| `allowlist` | Decision based on allowlist match |

---

### `VulnerabilityIdType`

Type of vulnerability identifier.

```typescript
type VulnerabilityIdType = 'CVE' | 'GHSA' | 'OSV' | 'OTHER';
```

---

## Lockfile Types

### `PnpmLockfile`

The pnpm lockfile structure passed to hooks.

```typescript
interface PnpmLockfile {
  lockfileVersion?: string | number;
  packages?: Record<string, LockfilePackageEntry>;
  importers?: Record<string, LockfileImporter>;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `lockfileVersion` | `string \| number` | Lockfile format version |
| `packages` | `Record<string, LockfilePackageEntry>` | Resolved packages map |
| `importers` | `Record<string, LockfileImporter>` | Workspace importers |

---

### `LockfilePackageEntry`

A package entry in the lockfile's `packages` section.

```typescript
interface LockfilePackageEntry {
  resolution?: LockfileResolution;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}
```

---

### `LockfileResolution`

Resolution information for a lockfile package.

```typescript
interface LockfileResolution {
  type?: string;
  directory?: string;
  path?: string;
  tarball?: string;
  integrity?: string;
}
```

---

### `LockfileImporter`

An importer entry (workspace root or workspace package).

```typescript
interface LockfileImporter {
  dependencies?: Record<string, LockfileDepVersion>;
  devDependencies?: Record<string, LockfileDepVersion>;
  optionalDependencies?: Record<string, LockfileDepVersion>;
  specifiers?: Record<string, string>;
}
```

---

### `LockfileDepVersion`

Version value from the lockfile — can be a plain string or an object.

```typescript
type LockfileDepVersion = string | { specifier?: string; version: string };
```

---

### `PnpmHookContext`

Context provided by pnpm to hook functions.

```typescript
interface PnpmHookContext {
  lockfileDir?: string;
  storeDir?: string;
  registries?: Record<string, string>;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `lockfileDir` | `string` | Directory containing the lockfile |
| `storeDir` | `string` | pnpm store directory |
| `registries` | `Record<string, string>` | Registry mappings |

---

## Vulnerability Types

### `VulnerabilityFinding`

A single vulnerability detected in a package.

```typescript
interface VulnerabilityFinding {
  id: string;
  source: FindingSource;
  packageName: string;
  packageVersion: string;
  title?: string;
  url?: string;
  description?: string;
  severity: Severity;
  cvssScore?: number;
  cvssVector?: string;
  publishedAt?: string;
  modifiedAt?: string;
  identifiers?: VulnerabilityIdentifier[];
  affectedRange?: string;
  fixedVersion?: string;
  dependencyChain?: string[];
  chainContext?: VulnerabilityChainContext;
  cvssDetails?: CvssFindingDetails;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `id` | `string` | Vulnerability identifier (e.g., `CVE-2021-44228`) |
| `source` | `FindingSource` | Source database |
| `packageName` | `string` | Affected package name |
| `packageVersion` | `string` | Affected version |
| `title` | `string` | Vulnerability title |
| `url` | `string` | Link to advisory |
| `description` | `string` | Detailed description |
| `severity` | `Severity` | Severity level |
| `cvssScore` | `number` | CVSS base score (0-10) |
| `cvssVector` | `string` | CVSS vector string |
| `publishedAt` | `string` | Publication date (ISO 8601) |
| `modifiedAt` | `string` | Last modification date |
| `identifiers` | `VulnerabilityIdentifier[]` | Additional identifiers |
| `affectedRange` | `string` | Affected version range |
| `fixedVersion` | `string` | Version that fixes the vulnerability |
| `dependencyChain` | `string[]` | Chain from direct dep to this package |
| `chainContext` | `VulnerabilityChainContext` | Enriched chain analysis |
| `cvssDetails` | `CvssFindingDetails` | Parsed CVSS details |

---

### `VulnerabilityIdentifier`

An identifier for a vulnerability.

```typescript
interface VulnerabilityIdentifier {
  type: VulnerabilityIdType;
  value: string;
}
```

**Example:**
```typescript
{
  type: 'CVE',
  value: 'CVE-2021-44228'
}
```

---

### `VulnerabilityChainContext`

Enriched context attached to a finding after dependency chain analysis.

```typescript
interface VulnerabilityChainContext {
  isDirect: boolean;
  chainDepth: number;
  numberOfPaths: number;
  totalAffected: number;
  propagatedSeverity: Severity;
  fixAvailable: boolean;
  isDevOnly: boolean;
  directAncestors: string[];
  riskFactors: RiskFactor[];
  compositeRiskScore: number;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `isDirect` | `boolean` | Whether this is a direct dependency |
| `chainDepth` | `number` | Depth from nearest direct dependency (0 = direct) |
| `numberOfPaths` | `number` | Distinct paths from direct deps |
| `totalAffected` | `number` | Total transitively affected packages |
| `propagatedSeverity` | `Severity` | Severity after chain adjustment |
| `fixAvailable` | `boolean` | Whether a fix exists |
| `isDevOnly` | `boolean` | Whether this is dev-only |
| `directAncestors` | `string[]` | Direct dependencies that chain to this |
| `riskFactors` | `RiskFactor[]` | Contributing risk factors |
| `compositeRiskScore` | `number` | Final risk score (0-10) |

---

### `CvssFindingDetails`

CVSS details parsed from the finding's vector.

```typescript
interface CvssFindingDetails {
  score: number;
  severity: Severity;
  attackVector: string;
  attackComplexity: string;
  privilegesRequired: string;
  userInteraction: string;
  scope: string;
  confidentiality: string;
  integrity: string;
  availability: string;
  exploitabilityLabel: string;
}
```

---

### `SourceStatus`

Status of a vulnerability source query.

```typescript
interface SourceStatus {
  ok: boolean;
  error?: string;
  durationMs: number;
}
```

---

## Policy Types

### `PackageRef`

Reference to a resolved package.

```typescript
interface PackageRef {
  name: string;
  version: string;
  registry?: string;
}
```

---

### `PolicyDecision`

A decision made for a vulnerability finding.

```typescript
interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  source: DecisionSource;
  at: string;
  findingId?: string;
  findingSeverity?: Severity;
  packageName?: string;
  packageVersion?: string;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `action` | `PolicyAction` | Action taken (allow/warn/block) |
| `reason` | `string` | Human-readable reason |
| `source` | `DecisionSource` | What triggered this decision |
| `at` | `string` | ISO 8601 timestamp |
| `findingId` | `string` | Associated vulnerability ID |
| `findingSeverity` | `Severity` | Severity at time of decision |
| `packageName` | `string` | Package name |
| `packageVersion` | `string` | Package version |

---

### `AllowlistEntry`

An entry in the allowlist that exempts specific findings.

```typescript
type AllowlistEntry = AllowlistEntryById | AllowlistEntryByPackage;
```

**By ID:**
```typescript
interface AllowlistEntryById {
  id: string;           // Required: CVE-XXXX-XXXX, GHSA-XXXX, etc.
  package?: string;     // Optional: additional package filter
  version?: string;     // Optional: semver range
  reason?: string;      // Optional: why it's allowed
  expires?: string;     // Optional: ISO 8601 expiration date
  directOnly?: boolean; // Optional: only for direct deps
}
```

**By Package:**
```typescript
interface AllowlistEntryByPackage {
  id?: string;          // Optional: additional ID filter
  package: string;      // Required: package name
  version?: string;     // Optional: semver range
  reason?: string;      // Optional: why it's allowed
  expires?: string;     // Optional: ISO 8601 expiration date
  directOnly?: boolean; // Optional: only for direct deps
}
```

---

## Configuration Types

### `AuditConfigInput`

User-provided configuration (all fields optional).

```typescript
interface AuditConfigInput {
  policy?: {
    block?: Severity[];
    warn?: Severity[];
    allowlist?: AllowlistEntry[];
    transitiveSeverityOverride?: 'downgrade-by-one';
  };
  sources?: {
    github?: boolean | { enabled?: boolean };
    nvd?: boolean | { enabled?: boolean };
    osv?: boolean | { enabled?: boolean };
  };
  performance?: { timeoutMs?: number };
  cache?: { ttlSeconds?: number };
  failOnNoSources?: boolean;
  failOnSourceError?: boolean;
  offline?: boolean;
  staticBaseline?: StaticBaselineConfigInput;
}
```

---

### `AuditConfig`

Fully-resolved configuration with all defaults applied.

```typescript
interface AuditConfig {
  policy: {
    block: Severity[];
    warn: Severity[];
    allowlist: AllowlistEntry[];
    transitiveSeverityOverride?: 'downgrade-by-one';
  };
  sources: {
    github: { enabled: boolean };
    nvd: { enabled: boolean };
    osv: { enabled: boolean };
  };
  performance: { timeoutMs: number };
  cache: { ttlSeconds: number };
  failOnNoSources: boolean;
  failOnSourceError: boolean;
  offline: boolean;
  staticBaseline: StaticBaselineConfig;
}
```

---

### `StaticBaselineConfig`

Configuration for the static vulnerability database.

```typescript
interface StaticBaselineConfig {
  enabled: boolean;
  cutoffDate: string;
  dataPath?: string;
}
```

---

### `StaticBaselineConfigInput`

User-provided static baseline configuration.

```typescript
interface StaticBaselineConfigInput {
  enabled?: boolean;
  cutoffDate?: string;
  dataPath?: string;
}
```

---

### `RuntimeOptions`

Runtime configuration for audit execution.

```typescript
interface RuntimeOptions {
  cwd: string;
  registryUrl: string;
  env: Record<string, string | undefined>;
}
```

---

## Dependency Graph Types

### `DependencyNode`

A node in the dependency graph.

```typescript
interface DependencyNode {
  name: string;
  version: string;
  isDirect: boolean;
  isDev: boolean;
  dependencies: string[];
}
```

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Package name |
| `version` | `string` | Package version |
| `isDirect` | `boolean` | Listed in importers |
| `isDev` | `boolean` | Dev-only dependency |
| `dependencies` | `string[]` | Forward edges (`name@version`) |

---

### `DependencyGraph`

Full dependency graph built from lockfile.

```typescript
interface DependencyGraph {
  nodes: Map<string, DependencyNode>;
  byName: Map<string, string[]>;
  dependents: Map<string, Set<string>>;
  directKeys: Set<string>;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `nodes` | `Map<string, DependencyNode>` | Nodes by `name@version` key |
| `byName` | `Map<string, string[]>` | Package name → all version keys |
| `dependents` | `Map<string, Set<string>>` | Reverse edges (who depends on me) |
| `directKeys` | `Set<string>` | Keys for direct dependencies |

---

### `PackageAuditResult`

Audit result for a single package.

```typescript
interface PackageAuditResult {
  pkg: PackageRef;
  findings: VulnerabilityFinding[];
}
```

---

## Risk Assessment Types

### `DependencyChainAnalysis`

Comprehensive dependency chain analysis.

```typescript
interface DependencyChainAnalysis {
  targetKey: string;
  shortestChain: string[] | null;
  allChains: string[][];
  impact: ImpactAnalysis;
  dependencyTree: string[];
  isDirect: boolean;
}
```

---

### `ImpactAnalysis`

Impact analysis for a vulnerable package.

```typescript
interface ImpactAnalysis {
  targetKey: string;
  directDependents: number;
  totalDependents: number;
  depth: number;
  breadth: number;
  riskScore: number;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `targetKey` | `string` | Package key (`name@version`) |
| `directDependents` | `number` | Direct dependents count |
| `totalDependents` | `number` | Total (transitive) dependents |
| `depth` | `number` | Max dependency chain depth |
| `breadth` | `number` | Max breadth at any level |
| `riskScore` | `number` | Calculated risk (0-10) |

---

### `RiskAssessment`

Risk assessment with CVSS integration.

```typescript
interface RiskAssessment {
  cvssScore: number;
  environmentalScore: number;
  temporalScore: number;
  compositeScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  factors: RiskFactor[];
}
```

---

### `RiskFactor`

An individual factor contributing to risk assessment.

```typescript
interface RiskFactor {
  name: string;
  description: string;
  weight: number;
  score: number;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Factor name |
| `description` | `string` | Human-readable description |
| `weight` | `number` | Weight (0-1) |
| `score` | `number` | Score contribution (0-10) |

---

## Type Guards

### Checking Severity

```typescript
import type { Severity } from 'pnpm-audit-hook';

const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];

function isValidSeverity(value: string): value is Severity {
  return (VALID_SEVERITIES as string[]).includes(value);
}
```

### Checking Finding Source

```typescript
import type { FindingSource } from 'pnpm-audit-hook';

const VALID_SOURCES: FindingSource[] = ['github', 'nvd', 'osv'];

function isValidSource(value: string): value is FindingSource {
  return (VALID_SOURCES as string[]).includes(value);
}
```

---

## Utility Types

### Severity Ordering

```typescript
import { SEVERITY_ORDER } from 'pnpm-audit-hook';

// ['critical', 'high', 'medium', 'low', 'unknown']

function severityIndex(sev: Severity): number {
  return SEVERITY_ORDER.indexOf(sev);
}

function isMoreSevere(a: Severity, b: Severity): boolean {
  return severityIndex(a) < severityIndex(b);
}
```
