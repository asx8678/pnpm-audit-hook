# pnpm-audit-hook

[![npm version](https://img.shields.io/npm/v/pnpm-audit-hook.svg)](https://www.npmjs.com/package/pnpm-audit-hook)
[![license](https://img.shields.io/npm/l/pnpm-audit-hook.svg)](https://github.com/asx8678/pnpm-audit-hook/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/pnpm-audit-hook.svg)](https://nodejs.org)

**Block vulnerable npm packages before they are downloaded.**

`pnpm-audit-hook` is a pre-download security gate for pnpm. It runs after dependency resolution and before package downloads, checks every resolved package against multiple vulnerability sources, and blocks installation when critical or high-severity issues are found.

Unlike `pnpm audit`, which runs after dependencies are already installed, `pnpm-audit-hook` prevents vulnerable code from reaching `node_modules` in the first place. Once configured, it works automatically with `pnpm install`, `pnpm add`, and `pnpm update`.

---

## Table of Contents

- [Why Use pnpm-audit-hook?](#why-use-pnpm-audit-hook)
- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Verify Installation](#verify-installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Allowlist](#allowlist)
- [Environment Variables](#environment-variables)
- [CLI Reference](#cli-reference)
- [Vulnerability Sources](#vulnerability-sources)
- [Caching](#caching)
- [CI/CD Integration](#cicd-integration)
- [Static Vulnerability Database](#static-vulnerability-database)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Local Development](#local-development)
- [Exit Codes](#exit-codes)
- [License](#license)

---

## Why Use pnpm-audit-hook?

Most dependency audit tools detect vulnerable packages after installation. `pnpm-audit-hook` moves that control earlier in the lifecycle by turning dependency installation into a policy-enforced security checkpoint.

It is designed for teams that need:

- **Pre-download protection** — vulnerable packages are blocked before they reach your machine.
- **Zero workflow disruption** — audits run automatically during normal pnpm commands.
- **Multiple vulnerability sources** — GitHub Advisory Database, OSV.dev, a bundled static database, and NVD enrichment.
- **Secure defaults** — critical and high-severity vulnerabilities are blocked by default.
- **CI/CD compatibility** — structured output, annotations, and pipeline-friendly exit codes.
- **Offline support** — the bundled static database can be used in air-gapped environments.

---

## Key Features

### Pre-Download Blocking

- Hooks into pnpm through `afterAllResolved`.
- Runs after dependency resolution but before package downloads.
- Blocks vulnerable packages before they enter `node_modules`.
- Works automatically with `pnpm install`, `pnpm add`, and `pnpm update`.

### Multiple Vulnerability Sources

- **GitHub Advisory Database** — real-time GHSA data.
- **OSV.dev** — aggregated vulnerability data from GHSA, npm, NVD, and other sources.
- **Bundled static database** — historical vulnerability data for offline and low-latency checks.
- **NVD enrichment** — CVSS and severity enrichment for findings with incomplete severity data.
- Sources are queried in parallel, then merged and deduplicated.

### Performance-Oriented Design

- Severity-aware file cache.
- Bloom filter for fast package-existence checks.
- Gzip-compressed static database shards.
- Compact static database indexes.
- Configurable API concurrency.

### Fail-Closed Security Model

- Source failures block installation by default.
- Invalid semver ranges are treated as potentially affected.
- Expired allowlist entries are ignored.
- Static database files are verified with SHA-256 integrity hashes.
- Cache reads and writes protect against symlink and path traversal attacks.
- Cache writes are atomic to reduce corruption risk.

### Flexible Policy Engine

- Configure `block`, `warn`, and `allow` behavior by severity.
- Allowlist vulnerabilities by CVE, GHSA, package, and version range.
- Add optional expiration dates to allowlist entries.
- Override blocking severity with environment variables for CI workflows.

### CI/CD Native

- GitHub Actions annotations using `::error::` and `::warning::`.
- Azure DevOps logging commands and task variables.
- JSON output for custom automation.
- Human-readable output for local development.
- Automatic CI detection for verbose pipeline logs.

### Offline and Air-Gapped Support

- Bundled static vulnerability database works without network access.
- `--offline` mode disables live API calls.
- Cached results can be reused until their TTL expires.

### Compact Status Banner

- Clean installs produce a single-line confirmation.
- Warning and blocked installs show concise CVE/GHSA details before the full report.
- Output remains readable for local development and CI logs.

### Developer Experience

- Sensible defaults require minimal setup.
- `pnpm-audit-scan` supports manual audits without installation.
- `.pnpm-audit.yaml` supports project-specific policy customization.
- Private registries are supported through `PNPM_REGISTRY` or `npm_config_registry`.
- Temporary bypass is available with `pnpm install --ignore-pnpmfile`.

---

## Quick Start

```bash
pnpm add -D pnpm-audit-hook
pnpm exec pnpm-audit-setup
```

After setup, every `pnpm install` runs a pre-download vulnerability audit automatically.

### Files Created During Setup

| File | Purpose |
|------|---------|
| `.pnpmfile.cjs` | pnpm hook entry point loaded automatically by pnpm |
| `.pnpm-audit.yaml` | Optional project security policy configuration |
| `.pnpm-audit-cache/` | Runtime cache directory created automatically |

Recommended commit commands:

```bash
git add .pnpmfile.cjs .pnpm-audit.yaml
echo ".pnpm-audit-cache/" >> .gitignore
git add .gitignore
```

---

## How It Works

```mermaid
flowchart LR
    A[pnpm install] --> B[Resolve Dependencies]
    B --> C[afterAllResolved Hook]
    C --> D{Audit Resolved Packages}
    D -->|Safe| E[Download and Install]
    D -->|Blocked Finding| F[Abort Install]
```

When pnpm resolves the dependency graph, `pnpm-audit-hook` receives the resolved lockfile through `.pnpmfile.cjs`. It extracts every package and version, checks the configured vulnerability sources, applies policy rules, and either allows pnpm to continue or aborts installation.

### Detailed Flow

```mermaid
flowchart TD
    A[pnpm command] --> B[Resolve dependency graph]
    B --> C[afterAllResolved hook]
    C --> D[Extract package list]
    D --> E[Load configuration]
    E --> F{Cache hit?}
    F -->|Yes| G[Use cached result]
    F -->|No| H[Query vulnerability sources]
    H --> I[Merge and deduplicate findings]
    I --> J{Missing severity?}
    J -->|Yes| K[Enrich with NVD]
    J -->|No| L[Apply policy]
    K --> L
    G --> L
    L --> M{Blocked findings?}
    M -->|Yes| N[Abort install]
    M -->|No| O[Warn if needed]
    O --> P[Continue install]
```

---

## Prerequisites

- **Node.js** 18 or later
- **pnpm** with `.pnpmfile.cjs` support, typically pnpm 6 or later

> This package is designed for pnpm projects. For npm, use `npm audit`; for Yarn, use `yarn audit`.

---

## Installation

### Per Project Recommended

```bash
pnpm add -D pnpm-audit-hook
pnpm exec pnpm-audit-setup
```

This installs the package, creates `.pnpmfile.cjs`, and creates `.pnpm-audit.yaml` if it does not already exist.

### Global Installation

Use global installation when you want to audit every pnpm project on your machine.

```bash
pnpm add -g pnpm-audit-hook
mkdir -p ~/.pnpm-hooks
cp $(pnpm root -g)/pnpm-audit-hook/dist ~/.pnpm-hooks/ -r
cp $(pnpm root -g)/pnpm-audit-hook/.pnpmfile.cjs ~/.pnpm-hooks/
pnpm config set global-pnpmfile ~/.pnpm-hooks/.pnpmfile.cjs
```

### From Source

```bash
git clone https://github.com/asx8678/pnpm-audit-hook.git
cd pnpm-audit-hook
pnpm install
pnpm run build

cp -r dist /path/to/your/project/
cp .pnpmfile.cjs /path/to/your/project/
```

### Upgrading from v1.1.0

When upgrading from v1.1.0, note the following changes:

- OSV.dev is enabled by default. Disable it with `sources.osv: false` or `PNPM_AUDIT_DISABLE_OSV=true`.
- Cache keys changed, so a one-time cache rebuild will occur automatically.
- Additional vulnerabilities may be reported because OSV.dev aggregates data from multiple databases.
- `--update-db` requires a source checkout because the update script is not included in a package installed from npm.

---

## Verify Installation

```bash
# Expected to succeed
pnpm add lodash

# Expected to be blocked because this version is known to be vulnerable
pnpm add event-stream@3.3.6
```

### Clean Install Output

```text
🛡️  pnpm-audit ── 142 packages ── github ✓  osv ✓  static-db ✓ ── ✅ clean ── 203ms
```

### Warning Output

Medium, low, and unknown-severity findings warn by default and allow installation to continue.

```text
🛡️  pnpm-audit ── 87 packages ── github ✓  osv ✓  static-db ✓ ── ⚠️  2 warnings (1 medium, 1 low) ── 312ms
  ⚠  CVE-2024-4067 [MEDIUM] micromatch@4.0.5 — ReDoS vulnerability
  ⚠  CVE-2024-4068 [MEDIUM] braces@3.0.2 — Uncontrolled resource consumption
```

### Blocked Install Output

Critical and high-severity findings block by default.

```text
🛡️  pnpm-audit ── 1 packages ── github ✓  osv ✓  static-db ✓ ── 🚫 1 BLOCKED ── 245ms
  🚫 GHSA-xxxx-xxxx-xxxx [CRITICAL] event-stream@3.3.6 — Malicious Package (fix: 4.0.0)

===============================================
           PNPM AUDIT SECURITY REPORT
===============================================

Source Status:
  github: OK (152ms)
  osv: OK (180ms)

Package Summary:
  Total packages scanned: 1
  Safe packages: 0
  Packages with vulnerabilities: 1

Vulnerabilities by Severity:
  CRITICAL: 1

Vulnerability Details:
  [CRITICAL] GHSA-xxxx-xxxx-xxxx
    Package: event-stream@3.3.6
    Title: Malicious Package in event-stream
    Affected: =3.3.6
    Fixed in: 4.0.0

===============================================
AUDIT FAILED - Installation blocked
===============================================
```

---

## Usage

### Automatic Mode

After setup, audits run automatically.

```bash
pnpm install                  # Audit runs automatically
pnpm add express              # New dependency is audited
pnpm add lodash@4.17.21       # Safe package installs normally
pnpm add event-stream@3.3.6   # Vulnerable package is blocked
```

### Manual Scan

Use the CLI to audit the current lockfile without installing packages.

```bash
pnpm-audit-scan                       # Human-readable output
pnpm-audit-scan --format json         # JSON output for CI or scripts
pnpm-audit-scan --severity critical   # Only block critical vulnerabilities
pnpm-audit-scan --offline             # Use static DB and cache only
```

### Output Formats

| Format | Use Case | Flag |
|--------|----------|------|
| `human` | Local terminal output | `--format human` |
| `json` | CI parsing and automation | `--format json` |
| `github` | GitHub Actions annotations | `--format github` |
| `azure` | Azure DevOps logging commands | `--format azure` |

### Default Finding Behavior

| Severity | Default Action | Result |
|----------|----------------|--------|
| `critical` | Block | Installation fails with exit code `1` |
| `high` | Block | Installation fails with exit code `1` |
| `medium` | Warn | Installation continues with exit code `2` for manual scans |
| `low` | Warn | Installation continues with exit code `2` for manual scans |
| `unknown` | Warn | Installation continues after enrichment is attempted |

---

## Configuration

Create `.pnpm-audit.yaml` in the project root.

```yaml
policy:
  block:
    - critical
    - high
  warn:
    - medium
    - low
    - unknown
  allowlist:
    - id: CVE-2024-12345
      reason: "False positive"
    - package: legacy-lib
      expires: "2025-06-01"

sources:
  github: true
  osv: true
  nvd: true

performance:
  timeoutMs: 15000

cache:
  ttlSeconds: 3600

staticBaseline:
  enabled: true
  cutoffDate: "2025-12-31"

failOnNoSources: true
failOnSourceError: true
offline: false
```

All fields are optional. Secure defaults are applied when fields are omitted.

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `policy.block` | Severities that abort installation | `["critical", "high"]` |
| `policy.warn` | Severities that log warnings | `["medium", "low", "unknown"]` |
| `policy.allowlist` | Exceptions to skip | `[]` |
| `sources.github` | Enable GitHub Advisory Database | `true` |
| `sources.osv` | Enable OSV.dev | `true` |
| `sources.nvd` | Enable NVD severity enrichment | `true` |
| `performance.timeoutMs` | API timeout in milliseconds | `15000` |
| `cache.ttlSeconds` | Default cache duration | `3600` |
| `staticBaseline.enabled` | Use the bundled static database | `true` |
| `staticBaseline.cutoffDate` | Static database coverage cutoff | `2025-12-31` |
| `staticBaseline.dataPath` | Custom static database path | Auto-detected |
| `failOnNoSources` | Block when no advisory sources are available | `true` |
| `failOnSourceError` | Block when an advisory source fails | `true` |
| `offline` | Skip live API calls | `false` |

### Source Toggles

```yaml
sources:
  github: true
  osv: true
  nvd: true
```

Equivalent environment variables:

```bash
PNPM_AUDIT_DISABLE_GITHUB=true pnpm install
PNPM_AUDIT_DISABLE_OSV=true pnpm install
```

### Offline Audit

```bash
pnpm-audit-scan --offline
PNPM_AUDIT_OFFLINE=true pnpm install
```

### Update the Vulnerability Database

```bash
pnpm-audit-scan --update-db
pnpm-audit-scan --update-db=full
GITHUB_TOKEN=your_token pnpm run update-vuln-db:incremental
```

---

## Allowlist

Allowlist entries suppress specific vulnerabilities or package findings. Use allowlists for documented exceptions, false positives, or temporary accepted risk.

```yaml
policy:
  allowlist:
    # By CVE or GHSA ID
    - id: CVE-2024-12345
      reason: "False positive for our use case"

    # By package name
    - package: legacy-lib
      reason: "Accepted risk while migration is in progress"
      expires: "2025-06-01"

    # Scoped to a specific vulnerability, package, and version range
    - id: CVE-2024-12345
      package: affected-pkg
      version: ">=1.0.0 <2.0.0"
      reason: "Only affects an unused feature"
      expires: "2025-12-31"
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | One of `id` or `package` | CVE or GHSA identifier, case-insensitive |
| `package` | One of `id` or `package` | Package name, case-insensitive |
| `version` | No | Optional semver range constraint |
| `reason` | No | Audit-trail documentation |
| `expires` | No | ISO date when the entry expires |

Expired entries are ignored automatically.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` / `GH_TOKEN` | GitHub API token for higher rate limits |
| `NVD_API_KEY` / `NIST_NVD_API_KEY` | NVD API key for higher rate limits |
| `PNPM_AUDIT_CONFIG_PATH` | Custom configuration file path |
| `PNPM_AUDIT_DISABLE_GITHUB` | Disable GitHub Advisory Database |
| `PNPM_AUDIT_DISABLE_OSV` | Disable OSV.dev |
| `PNPM_AUDIT_BLOCK_SEVERITY` | Override block severities, for example `critical,high,medium` |
| `PNPM_AUDIT_QUIET` | Suppress non-error output |
| `PNPM_AUDIT_DEBUG` | Enable debug logging |
| `PNPM_AUDIT_VERBOSE` | Enable verbose logging |
| `PNPM_AUDIT_JSON` | Emit JSON output |
| `PNPM_AUDIT_FORMAT` | Output format: `human`, `azure`, `github`, or `json` |
| `PNPM_AUDIT_OFFLINE` | Use only the static database and cache |
| `PNPM_AUDIT_FAIL_ON_NO_SOURCES` | Fail when no advisory sources are available |
| `PNPM_AUDIT_FAIL_ON_SOURCE_ERROR` | Fail when an advisory source errors |
| `PNPM_AUDIT_GITHUB_CONCURRENCY` | Maximum concurrent GitHub API requests |
| `PNPM_REGISTRY` / `npm_config_registry` | Custom npm registry URL |

Verbose mode is enabled automatically in common CI environments, including `CI`, `GITHUB_ACTIONS`, `TF_BUILD`, `GITLAB_CI`, and `JENKINS_URL`.

---

## CLI Reference

`pnpm-audit-scan` supports the following flags.

| Flag | Description |
|------|-------------|
| `--format <format>` | Output format: `human`, `json`, `azure`, or `github` |
| `--severity <list>` | Comma-separated severities to block |
| `--offline` | Skip live API calls and use only the static database and cache |
| `--update-db` | Run an incremental vulnerability database update |
| `--update-db=full` | Run a full vulnerability database rebuild |
| `--quiet` | Suppress non-error output |
| `--verbose` | Enable verbose output |
| `--debug` | Enable debug output |
| `--config <path>` | Use a custom configuration file |
| `--help` | Show help text |
| `--version` | Show version |

When `--update-db` is used, the database update runs and the CLI exits without performing an audit.

---

## Vulnerability Sources

```mermaid
flowchart TD
    subgraph PRIMARY["Primary Sources"]
        A[Static Database]
        B[GitHub Advisory API]
        C[OSV.dev API]
    end

    A --> D[Merge and Deduplicate]
    B --> D
    C --> D
    D --> E{Unknown Severity?}
    E -->|Yes| F[NVD Enrichment]
    E -->|No| G[Final Findings]
    F --> G
```

| Source | Type | Purpose | Rate Limits / Notes |
|--------|------|---------|---------------------|
| Static DB | Bundled | Historical vulnerability checks and offline support | No API required |
| GitHub Advisory | API | Current GHSA vulnerability data | 60 requests/hour without token; 5,000 requests/hour with token |
| OSV.dev | API | Aggregated vulnerability data from GHSA, npm, NVD, and other databases | Free; no key required |
| NVD | API | CVSS and severity enrichment | 5 requests/30 seconds without key; 50 requests/30 seconds with key |

### Query Strategy

```mermaid
sequenceDiagram
    participant H as Hook
    participant C as Cache
    participant S as Static DB
    participant G as GitHub API
    participant O as OSV.dev API
    participant N as NVD API

    H->>C: Check package@version
    alt Cache hit
        C-->>H: Return cached findings
    else Cache miss
        H->>S: Query bundled database
        par Live sources
            H->>G: Query GitHub Advisory API
        and
            H->>O: Query OSV.dev API
        end
        H->>H: Merge and deduplicate
        opt Unknown severity
            H->>N: Enrich severity
        end
        H->>C: Cache result
    end
```

---

## Caching

The cache reduces repeated API calls and improves install performance.

```mermaid
flowchart LR
    A[Package Query] --> B{Cache Exists?}
    B -->|Yes| C{Expired?}
    C -->|No| D[Return Cached Result]
    C -->|Yes| E[Query Sources]
    B -->|No| E
    E --> F[Write Cache Entry]
    F --> G[Return Result]
```

### Cache Location

```text
.pnpm-audit-cache/
├── ab/
│   └── ab1234...def.json
├── cd/
│   └── cd5678...ghi.json
└── ...
```

### Dynamic TTL

| Severity | TTL | Rationale |
|----------|-----|-----------|
| Critical | 15 minutes | Refresh quickly for high-risk findings |
| High | 30 minutes | Keep significant findings current |
| Medium | 1 hour | Standard refresh interval |
| Low / Unknown | Configured TTL | Use project default |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Install with Audit
on: [push, pull_request]

jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
```

The hook runs during `pnpm install` and fails the job when blocking vulnerabilities are found.

GitHub Actions output includes annotations and optional outputs for downstream steps.

| Output | Description |
|--------|-------------|
| `audit-blocked` | `true` when installation is blocked |
| `vulnerability-count` | Total vulnerability count |
| `critical-count` | Number of critical vulnerabilities |
| `high-count` | Number of high vulnerabilities |

### Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: NodeTool@0
    inputs:
      version: 20
  - script: |
      npm install -g pnpm
      pnpm install
    displayName: Install with Audit
    env:
      GITHUB_TOKEN: $(GITHUB_TOKEN)
      NVD_API_KEY: $(NVD_API_KEY)
      PNPM_AUDIT_FORMAT: azure
```

Azure DevOps output uses pipeline logging commands for grouped output, errors, warnings, and task variables. Azure Pipelines are auto-detected when `TF_BUILD=True`.

| Variable | Description |
|----------|-------------|
| `AUDIT_BLOCKED` | `true` when installation is blocked |
| `AUDIT_VULNERABILITY_COUNT` | Total vulnerability count |
| `AUDIT_CRITICAL_COUNT` | Number of critical vulnerabilities |
| `AUDIT_HIGH_COUNT` | Number of high vulnerabilities |

---

## Static Vulnerability Database

`pnpm-audit-hook` includes a bundled vulnerability database for historical findings. This reduces API usage, improves performance, and supports offline audits.

### Benefits

- Faster checks for known historical vulnerabilities.
- Offline and air-gapped operation.
- Reduced dependency on external API availability.
- Fewer rate-limit issues in CI.

### Integrity Verification

Static database shard files include SHA-256 hashes generated during the build. At runtime, the reader verifies these hashes before using the data. If a shard is modified or corrupted, the integrity check detects it.

### Compression and Optimization

The build process optimizes the static database automatically:

- Compact index keys reduce index size.
- Large shard files are gzip-compressed.
- Small shards remain uncompressed for fast reads.
- The runtime reader handles both `.json` and `.json.gz` files transparently.

Optimization runs through `scripts/optimize-static-db.js` during `pnpm run build`.

### Updating the Database

The database is built from the GitHub Advisory Database through a GraphQL query. The update script fetches npm ecosystem advisories, normalizes them, groups them by package, deduplicates by advisory ID, and writes one shard per affected package.

```bash
pnpm run update-vuln-db:incremental
pnpm run update-vuln-db
pnpm run update-vuln-db:full
pnpm run update-vuln-db -- --sample
pnpm run update-vuln-db -- --cutoff=2024-06-30T23:59:59Z
```

A GitHub token is recommended for faster updates:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

After updating, rebuild and commit the generated data.

```bash
pnpm run build
git add src/static-db/data/ dist/static-db/data/
git commit -m "chore: update vulnerability database"
```

### Generated File Structure

Source data:

```text
src/static-db/data/
├── index.json
├── lodash.json
├── axios.json
├── @angular/
│   └── core.json
└── ...
```

Optimized build output:

```text
dist/static-db/data/
├── index.json.gz
├── lodash.json
├── @angular/
│   └── core.json
├── directus.json.gz
└── ...
```

For packaging alternatives and tradeoffs, see [`docs/db-packaging-evaluation.md`](docs/db-packaging-evaluation.md).

---

## Architecture

```mermaid
classDiagram
    class PnpmHook {
        +afterAllResolved(lockfile, context)
    }

    class AuditEngine {
        +runAudit(lockfile, runtime)
        -extractPackages(lockfile)
        -aggregateVulnerabilities(packages)
        -evaluatePolicies(findings)
    }

    class VulnerabilitySource {
        <<interface>>
        +query(packageName, version)
    }

    class StaticDatabase {
        +query(packageName, version)
        -loadShard(packageName)
        -bloomFilter
    }

    class GitHubAdvisory {
        +query(packageName, version)
        -fetchFromAPI()
        -rateLimiter
    }

    class OsvSource {
        +query(packageName, version)
        -fetchFromAPI()
    }

    class NVDEnricher {
        +enrichSeverity(findings)
        -fetchCVSS(cveId)
    }

    class PolicyEngine {
        +evaluate(findings, config)
        -checkAllowlist(finding)
        -checkSeverity(finding)
    }

    class FileCache {
        +get(key)
        +set(key, value, ttl)
        +prune()
    }

    PnpmHook --> AuditEngine
    AuditEngine --> VulnerabilitySource
    AuditEngine --> PolicyEngine
    AuditEngine --> FileCache
    VulnerabilitySource <|.. StaticDatabase
    VulnerabilitySource <|.. GitHubAdvisory
    VulnerabilitySource <|.. OsvSource
    GitHubAdvisory --> NVDEnricher
```

---

## Security Model

### Fail-Closed Defaults

| Condition | Default Behavior |
|-----------|------------------|
| Advisory source fails | Block installation |
| All sources are disabled | Block installation |
| Invalid allowlist entry | Ignore the entry |
| Expired allowlist entry | Ignore the entry |
| Unknown severity | Warn and attempt enrichment |
| Invalid vulnerability semver | Treat as potentially affected |

### Security Controls

- Pre-download blocking prevents vulnerable packages from reaching `node_modules`.
- API credentials are read only from environment variables.
- File paths and package names are validated to reduce path traversal risk.
- Cache reads and writes detect symlinks.
- Cache writes use a temporary file and atomic rename.
- Static database files are protected with SHA-256 integrity checks.
- Cache key versioning invalidates stale cached data after database updates.

---

## Troubleshooting

### `AUDIT FAILED` — How do I unblock installation?

One-time bypass:

```bash
pnpm install --ignore-pnpmfile
```

Investigate findings:

```bash
pnpm-audit-scan --format json | jq '.findings'
```

Recommended fixes:

1. Upgrade the vulnerable package to a patched version.
2. Allowlist the vulnerability if it is a verified false positive.
3. Adjust `policy.block` in `.pnpm-audit.yaml` if your policy requires a different threshold.

### OSV.dev or GitHub API is unreachable

Use offline mode:

```bash
PNPM_AUDIT_OFFLINE=true pnpm install
```

Disable a specific source:

```bash
PNPM_AUDIT_DISABLE_OSV=true pnpm install
PNPM_AUDIT_DISABLE_GITHUB=true pnpm install
```

Disable fail-closed behavior for source errors:

```yaml
failOnSourceError: false
```

### Audits are slow

- Set `GITHUB_TOKEN` to increase GitHub API rate limits.
- Reuse `.pnpm-audit-cache/` between CI runs where appropriate.
- Use offline mode for the fastest audits when live source checks are not required.

### Verbose logging appears in CI

Verbose mode is auto-enabled in common CI environments. To suppress it:

```bash
PNPM_AUDIT_QUIET=true pnpm install
```

### Static database was updated but old results still appear

Cache keys include database version information, so stale entries should invalidate automatically. To force a refresh:

```bash
rm -rf .pnpm-audit-cache/
pnpm install
```

---

## Uninstall

### Per Project

```bash
rm .pnpmfile.cjs
pnpm remove pnpm-audit-hook
rm -f .pnpm-audit.yaml
rm -rf .pnpm-audit-cache/
```

Removing `.pnpmfile.cjs` is enough to disable the hook. The package can remain installed without affecting pnpm commands.

### Global Installation

```bash
pnpm config delete global-pnpmfile
rm -rf ~/.pnpm-hooks
pnpm remove -g pnpm-audit-hook
```

### Temporarily Disable

```bash
mv .pnpmfile.cjs .pnpmfile.cjs.disabled
mv .pnpmfile.cjs.disabled .pnpmfile.cjs
```

Bypass once:

```bash
pnpm install --ignore-pnpmfile
```

---

## Local Development

### Setup

```bash
git clone https://github.com/asx8678/pnpm-audit-hook.git
cd pnpm-audit-hook
pnpm install
pnpm run build
```

### Test Directly

```bash
pnpm run build
pnpm add lodash
pnpm add event-stream@3.3.6
```

### Run Tests

```bash
pnpm test
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success; no blocking vulnerabilities |
| `1` | Critical or high-severity vulnerability blocked |
| `2` | Warning-level vulnerabilities found |
| `3` | Source error under fail-closed policy |

---

## License

MIT
