# Audit API

> Core audit functionality for running security scans on pnpm lockfiles.

## Overview

The Audit API provides the main entry point for running vulnerability audits against pnpm lockfiles. It orchestrates multiple vulnerability sources, applies policy rules, and returns structured results.

## Functions

### `runAudit(lockfile, runtime)`

Runs a complete audit on the provided lockfile against all configured vulnerability sources.

```typescript
async function runAudit(
  lockfile: PnpmLockfile,
  runtime: RuntimeOptions
): Promise<AuditResult>
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `lockfile` | `PnpmLockfile` | The resolved pnpm lockfile structure |
| `runtime` | `RuntimeOptions` | Runtime configuration (cwd, env, registry) |

#### Returns

`Promise<AuditResult>` — Complete audit result with findings, decisions, and metadata.

#### Example

```typescript
import { runAudit } from 'pnpm-audit-hook';
import fs from 'node:fs/promises';
import YAML from 'yaml';

// Load your lockfile
const lockfileContent = await fs.readFile('pnpm-lock.yaml', 'utf-8');
const lockfile = YAML.parse(lockfileContent);

// Run the audit
const result = await runAudit(lockfile, {
  cwd: process.cwd(),
  registryUrl: 'https://registry.npmjs.org',
  env: process.env,
});

// Check results
if (result.blocked) {
  console.error(`Audit blocked: ${result.findings.length} vulnerabilities found`);
  for (const finding of result.findings) {
    console.error(`  - ${finding.packageName}@${finding.packageVersion}: ${finding.severity}`);
  }
}

console.log(`Audited ${result.totalPackages} packages in ${result.durationMs}ms`);
```

#### Behavior

1. **Config Loading** — Loads configuration from `.pnpm-audit.yaml` or environment variables
2. **Lockfile Validation** — Validates lockfile structure for security
3. **Package Extraction** — Extracts all packages from the lockfile
4. **Vulnerability Aggregation** — Queries GitHub Advisory, NVD, OSV, and static DB
5. **Dependency Analysis** — Builds dependency graph and traces chains
6. **Risk Scoring** — Enriches findings with CVSS details and risk scores
7. **Policy Evaluation** — Applies allow/block/warn rules per finding
8. **Result Compilation** — Aggregates all decisions and builds summary

#### Error Handling

- Throws if config file has YAML syntax errors
- Throws if config contains security violations (path traversal, malicious content)
- Logs warnings for invalid config values but continues with defaults
- Source failures are recorded in `sourceStatus` and can optionally block installation

---

### `createPnpmHooks()`

Creates a pnpm hooks object that can be exported from `.pnpmfile.cjs` for automatic auditing.

```typescript
function createPnpmHooks(): PnpmHooks
```

#### Returns

`PnpmHooks` — Object with `hooks.afterAllResolved` function.

#### Example

**.pnpmfile.cjs**
```javascript
const { createPnpmHooks } = require('pnpm-audit-hook');

module.exports = createPnpmHooks();
```

#### How It Works

The `afterAllResolved` hook:
1. Receives the resolved lockfile from pnpm
2. Extracts runtime info (cwd, registry URL, environment)
3. Calls `runAudit()` internally
4. Throws an error if the audit blocks installation
5. Returns the lockfile unchanged if the audit passes

#### Error Message Format

When blocking, the error includes detailed information:

```
pnpm-audit-hook blocked installation (2 issues in 2 packages):
  [HIGH] lodash@4.17.21 CVE-2021-23337 (fix: 4.17.22)
  [CRITICAL] axios@0.21.1 GHSA-4w2v-q235-vp99
```

---

## Interfaces

### `AuditResult`

Complete result of an audit run.

```typescript
interface AuditResult {
  /** Whether installation should be blocked */
  blocked: boolean;

  /** Whether warnings were generated */
  warnings: boolean;

  /** Policy decisions for each finding */
  decisions: PolicyDecision[];

  /** Process exit code (0=success, 1=blocked, 2=warnings, 3=source error) */
  exitCode: number;

  /** All vulnerability findings across all packages */
  findings: VulnerabilityFinding[];

  /** Status of each vulnerability source */
  sourceStatus: Record<string, SourceStatus>;

  /** Total number of packages audited */
  totalPackages: number;

  /** Audit duration in milliseconds */
  durationMs: number;

  /** Cache performance statistics */
  cacheStats?: {
    hitRate: number;
    totalEntries: number;
    totalSizeBytes: number;
    averageReadTimeMs: number;
    averageWriteTimeMs: number;
  };
}
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `blocked` | `boolean` | `true` if any finding triggered a block decision |
| `warnings` | `boolean` | `true` if any finding triggered a warn decision |
| `decisions` | `PolicyDecision[]` | Array of all policy decisions made |
| `exitCode` | `number` | Recommended process exit code |
| `findings` | `VulnerabilityFinding[]` | All vulnerability findings (enriched with chain context) |
| `sourceStatus` | `Record<string, SourceStatus>` | Status of each queried source |
| `totalPackages` | `number` | Number of packages in the lockfile |
| `durationMs` | `number` | Wall-clock time for the audit |
| `cacheStats` | `CacheStats` | Cache hit rates and performance metrics |

---

### `RuntimeOptions`

Runtime configuration for audit execution.

```typescript
interface RuntimeOptions {
  /** Working directory for config loading and cache storage */
  cwd: string;

  /** Registry URL for package resolution */
  registryUrl: string;

  /** Environment variables (typically process.env) */
  env: Record<string, string | undefined>;
}
```

---

### `PnpmHooks`

Type for the pnpm hooks export.

```typescript
interface PnpmHooks {
  hooks: {
    afterAllResolved: (
      lockfile: PnpmLockfile,
      context: PnpmHookContext
    ) => Promise<PnpmLockfile>;
  };
}
```

---

## Constants

### `EXIT_CODES`

Process exit codes for different audit outcomes.

```typescript
const EXIT_CODES = {
  SUCCESS: 0,      // No blocking issues
  BLOCKED: 1,      // Installation blocked
  WARNINGS: 2,     // Warnings only (non-blocking)
  SOURCE_ERROR: 3, // Vulnerability source failed
} as const;
```

#### Usage

```typescript
import { runAudit, EXIT_CODES } from 'pnpm-audit-hook';

const result = await runAudit(lockfile, runtime);

// Use the exit code directly
process.exit(result.exitCode);

// Or check specific conditions
if (result.exitCode === EXIT_CODES.SOURCE_ERROR) {
  console.warn('Some vulnerability sources failed');
}
```

---

## Advanced Usage

### Custom Policy Evaluation

```typescript
import { runAudit, type AuditConfigInput } from 'pnpm-audit-hook';

// Create a config that only blocks critical vulnerabilities
const customConfig: AuditConfigInput = {
  policy: {
    block: ['critical'],
    warn: ['high', 'medium', 'low', 'unknown'],
  },
};

// The config is loaded automatically from .pnpm-audit.yaml
// or you can write it to a temp file
```

### Offline Mode

```typescript
// Skip all API calls, use only static DB + cache
process.env.PNPM_AUDIT_OFFLINE = 'true';

const result = await runAudit(lockfile, {
  cwd: process.cwd(),
  registryUrl: 'https://registry.npmjs.org',
  env: process.env,
});
```

### Analyzing Results

```typescript
const result = await runAudit(lockfile, runtime);

// Group findings by severity
const bySeverity = result.findings.reduce((acc, f) => {
  (acc[f.severity] ??= []).push(f);
  return acc;
}, {} as Record<string, VulnerabilityFinding[]>);

console.log(`Critical: ${bySeverity.critical?.length ?? 0}`);
console.log(`High: ${bySeverity.high?.length ?? 0}`);
console.log(`Medium: ${bySeverity.medium?.length ?? 0}`);

// Find fixable vulnerabilities
const fixable = result.findings.filter(f => f.fixedVersion);
console.log(`\n${fixable.length} vulnerabilities have fixes available:`);
for (const f of fixable) {
  console.log(`  ${f.packageName}: ${f.fixedVersion}`);
}
```

### Filtering by Source

```typescript
// Check which sources contributed findings
const findingsBySource = result.findings.reduce((acc, f) => {
  (acc[f.source] ??= []).push(f);
  return acc;
}, {} as Record<string, VulnerabilityFinding[]>);

console.log('Findings by source:');
for (const [source, findings] of Object.entries(findingsBySource)) {
  console.log(`  ${source}: ${findings.length}`);
}
```
