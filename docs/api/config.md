# Configuration API

> Loading, validating, and managing pnpm-audit-hook configuration.

## Overview

pnpm-audit-hook uses YAML configuration files (`.pnpm-audit.yaml`) with optional environment variable overrides. The Configuration API provides programmatic access to load and validate this configuration.

## Functions

### `loadConfig(opts)`

Loads and validates the audit configuration from file and environment variables.

```typescript
async function loadConfig(opts: LoadConfigOptions): Promise<AuditConfig>
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `opts` | `LoadConfigOptions` | Options containing `cwd` and `env` |

#### Returns

`Promise<AuditConfig>` — Fully-resolved configuration with all defaults applied.

#### Example

```typescript
import { loadConfig } from 'pnpm-audit-hook/config';

const config = await loadConfig({
  cwd: process.cwd(),
  env: process.env,
});

console.log('Block severities:', config.policy.block);
console.log('GitHub source:', config.sources.github.enabled);
console.log('Timeout:', config.performance.timeoutMs, 'ms');
```

#### Behavior

1. **Config File Resolution**
   - Checks `PNPM_AUDIT_CONFIG_PATH` environment variable first
   - Falls back to `.pnpm-audit.yaml` in the `cwd`
   - Uses defaults if no config file exists

2. **Environment Variable Overrides**
   - `PNPM_AUDIT_BLOCK_SEVERITY` — Override block severities
   - `PNPM_AUDIT_FAIL_ON_NO_SOURCES` — Override fail-on-no-sources
   - `PNPM_AUDIT_FAIL_ON_SOURCE_ERROR` — Override fail-on-source-error
   - `PNPM_AUDIT_OFFLINE` — Enable offline mode

3. **Validation**
   - Validates severity values against allowed set
   - Validates timeout and cache TTL bounds
   - Validates allowlist entries
   - Validates static baseline configuration
   - Warns on unrecognized config keys (with typo suggestions)
   - Checks for security issues (path traversal, malicious content)

4. **Defaults Applied**
   - Missing values use sensible defaults
   - Invalid values are replaced with defaults and logged

---

## Interfaces

### `LoadConfigOptions`

Options for the `loadConfig` function.

```typescript
interface LoadConfigOptions {
  /** Working directory for config file resolution */
  cwd: string;

  /** Environment variables for overrides */
  env: Record<string, string | undefined>;
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
  performance: {
    timeoutMs: number;
  };
  cache: {
    ttlSeconds: number;
  };
  failOnNoSources: boolean;
  failOnSourceError: boolean;
  offline: boolean;
  staticBaseline: StaticBaselineConfig;
}
```

---

### `AuditConfigInput`

User-provided configuration (all fields optional, merged with defaults).

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
  performance?: {
    timeoutMs?: number;
  };
  cache?: {
    ttlSeconds?: number;
  };
  failOnNoSources?: boolean;
  failOnSourceError?: boolean;
  offline?: boolean;
  staticBaseline?: StaticBaselineConfigInput;
}
```

---

### `StaticBaselineConfig`

Configuration for the static vulnerability database.

```typescript
interface StaticBaselineConfig {
  /** Enable/disable static baseline (default: true) */
  enabled: boolean;

  /** Vulnerabilities before this date use static DB (ISO date string) */
  cutoffDate: string;

  /** Optional custom path to static data directory */
  dataPath?: string;
}
```

---

## Configuration File Format

### Basic Structure

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
    - high
  warn:
    - medium
    - low
    - unknown
  allowlist: []

sources:
  github:
    enabled: true
  nvd:
    enabled: true
  osv:
    enabled: true

performance:
  timeoutMs: 15000

cache:
  ttlSeconds: 3600

failOnNoSources: true
failOnSourceError: true
offline: false

staticBaseline:
  enabled: true
  cutoffDate: "2025-01-01"
```

### Policy Configuration

```yaml
policy:
  # Severities that block installation
  block:
    - critical
    - high

  # Severities that warn but don't block
  warn:
    - medium
    - low
    - unknown

  # Exceptions to the policy
  allowlist:
    # Allow a specific CVE
    - id: CVE-2021-44228
      reason: "Not applicable to our usage"
      expires: "2025-06-01"

    # Allow a specific package
    - package: lodash
      version: ">=4.17.21"
      reason: "Risk accepted by security team"

    # Allow only for direct dependencies
    - package: moment
      directOnly: true
      reason: "Dev dependency, low risk"

    # Combined ID and package match
    - id: GHSA-xxxx-xxxx
      package: axios
      version: ">=0.21.0 <1.0.0"
      reason: "Mitigated by network controls"
```

#### Allowlist Entry Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | One of id/package | Vulnerability ID (CVE-XXXX, GHSA-XXXX, etc.) |
| `package` | One of id/package | Package name (case-insensitive) |
| `version` | No | Semver range constraint (e.g., `>=1.0.0`) |
| `reason` | No | Explanation for the exception |
| `expires` | No | ISO 8601 date when the exception expires |
| `directOnly` | No | If `true`, only applies to direct dependencies |

### Source Configuration

```yaml
sources:
  # Enable/disable individual sources
  github:
    enabled: true
  nvd:
    enabled: false  # Disable NVD for faster audits
  osv:
    enabled: true
```

### Performance Configuration

```yaml
performance:
  # Timeout per source query in milliseconds (max: 300000)
  timeoutMs: 15000
```

### Cache Configuration

```yaml
cache:
  # How long to cache source responses in seconds (max: 86400)
  ttlSeconds: 3600
```

### Static Baseline Configuration

```yaml
staticBaseline:
  # Enable the bundled static vulnerability database
  enabled: true

  # Vulnerabilities published before this date use the static DB
  cutoffDate: "2025-01-01"

  # Optional: custom path to static data directory
  # dataPath: "./custom-static-db"
```

---

## Environment Variables

All environment variables override their corresponding config file values.

### Core Variables

| Variable | Config Equivalent | Default | Description |
|----------|-------------------|---------|-------------|
| `PNPM_AUDIT_CONFIG_PATH` | — | `.pnpm-audit.yaml` | Path to config file (relative to cwd) |
| `PNPM_AUDIT_BLOCK_SEVERITY` | `policy.block` | `critical,high` | Comma-separated severities to block |
| `PNPM_AUDIT_FAIL_ON_NO_SOURCES` | `failOnNoSources` | `true` | Fail when all sources disabled |
| `PNPM_AUDIT_FAIL_ON_SOURCE_ERROR` | `failOnSourceError` | `true` | Fail when source errors occur |
| `PNPM_AUDIT_OFFLINE` | `offline` | `false` | Use only static DB + cache |

### Color Variables

| Variable | Description |
|----------|-------------|
| `NO_COLOR` | Disable all color output ([no-color.org](https://no-color.org)) |
| `FORCE_COLOR` | Force color output (0 = disable, 1+ = enable) |
| `COLORTERM` | Terminal color support (`truecolor` or `24bit`) |
| `TERM` | Terminal type (checked for `color` or `256color`) |

---

## Defaults

The following defaults are used when no configuration is provided:

```typescript
const DEFAULT_CONFIG: AuditConfig = {
  policy: {
    block: ['critical', 'high'],
    warn: ['medium', 'low', 'unknown'],
    allowlist: [],
  },
  sources: {
    github: { enabled: true },
    nvd: { enabled: true },
    osv: { enabled: true },
  },
  performance: {
    timeoutMs: 15000,
  },
  cache: {
    ttlSeconds: 3600,
  },
  failOnNoSources: true,
  failOnSourceError: true,
  offline: false,
  staticBaseline: {
    enabled: true,
    cutoffDate: '<bundled-db-cutoff>',
  },
};
```

---

## Validation Rules

### Severity Values

Allowed severity values: `critical`, `high`, `medium`, `low`, `unknown`

Invalid values are filtered out with a warning. If a severity value looks similar to a valid one, a suggestion is provided.

### Numeric Bounds

| Parameter | Min | Max | Default |
|-----------|-----|-----|---------|
| `timeoutMs` | 1 | 300000 (5 min) | 15000 |
| `ttlSeconds` | 1 | 86400 (24 hr) | 3600 |

### Security Checks

- Config paths must be relative (no absolute paths or `..` traversal)
- Content is scanned for malicious patterns
- YAML parse errors include line/column info

---

## Error Messages

### Config File Not Found

```
No config file found at /path/to/.pnpm-audit.yaml, using defaults
```

This is a debug message, not an error. Defaults are used.

### YAML Parse Error

```
Failed to read config at /path/to/.pnpm-audit.yaml: 
  unexpected end of stream at line 5, column 3
```

### Invalid Config Values

```
Invalid severity values ignored: critcal, hihg
  Suggestions: "critcal" -> did you mean "critical"?
  Valid severities: critical, high, medium, low, unknown
```

### Unrecognized Config Keys

```
Unrecognized config key "polciy" — did you mean "policy"?
  See https://github.com/asx8678/pnpm-audit-hook#configuration
```

---

## Examples

### Minimal Configuration

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
```

### Production Configuration

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
    - high
  warn:
    - medium
  allowlist:
    - package: typescript
      reason: "Dev dependency, no runtime risk"
      directOnly: true

sources:
  github: { enabled: true }
  nvd: { enabled: false }
  osv: { enabled: true }

performance:
  timeoutMs: 30000

cache:
  ttlSeconds: 7200

staticBaseline:
  enabled: true
```

### Development Configuration

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
  warn:
    - high
    - medium

performance:
  timeoutMs: 10000

cache:
  ttlSeconds: 1800
```

### Offline Configuration

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
    - high

offline: true

staticBaseline:
  enabled: true
```
