# pnpm-audit-hook

[![npm version](https://img.shields.io/npm/v/pnpm-audit-hook.svg)](https://www.npmjs.com/package/pnpm-audit-hook)
[![license](https://img.shields.io/npm/l/pnpm-audit-hook.svg)](https://github.com/asx8678/pnpm-audit-hook/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/pnpm-audit-hook.svg)](https://nodejs.org)

**Stop vulnerable packages before they reach your machine.** pnpm-audit-hook is a security hook for pnpm that intercepts `pnpm install` after dependency resolution but **before any packages are downloaded**. It checks every resolved package against multiple vulnerability databases and blocks the install if critical or high severity issues are found — so vulnerable code never touches your `node_modules`.

### Why pnpm-audit-hook?

Unlike `pnpm audit` which runs *after* install, this hook acts as a **gatekeeper** — vulnerable packages are rejected before download. It works transparently on every `pnpm install`, `pnpm add`, and `pnpm update` with zero workflow changes.

## Features

### 🛡️ Pre-Download Blocking
- Intercepts pnpm's `afterAllResolved` hook — **blocks before download**, not after
- Vulnerable code never reaches your machine or `node_modules`
- Works on `pnpm install`, `pnpm add`, and `pnpm update` automatically

### 🔍 Multiple Vulnerability Sources (Queried in Parallel)
- **GitHub Advisory Database** — real-time GHSA data (60 req/hr free, 5,000/hr with token)
- **OSV.dev** — aggregates GHSA + npm + NVD + more, free, no auth needed
- **Bundled Static Database** — 1,900+ packages with historical vulns (2020-2025), works offline
- **NVD Enrichment** — fills in missing CVSS scores and severity levels
- Sources run in parallel for speed; results are merged and deduplicated

### ⚡ Performance
- **Smart caching** — file-based cache with severity-aware TTL (critical: 15 min, high: 30 min, medium: 1 hr)
- **Bloom filter** — O(1) package existence check before loading any shard from static DB
- **Gzip compression** — static DB is compressed at build time, reducing npm tarball by ~3-5x
- **Optimized index** — compact field names reduce index size by ~80%
- **Concurrent API queries** — configurable concurrency for GitHub (up to 50) and OSV (5)

### 🔒 Fail-Closed Security Model
- **API failure = block** — if a source is unreachable, install is blocked by default (configurable)
- **Invalid semver = affected** — ambiguous version ranges are treated as vulnerable
- **Expired allowlist = enforced** — once an allowlist entry expires, the vulnerability blocks again
- **DB integrity verification** — SHA-256 hashes detect tampered vulnerability data in `node_modules`
- **Symlink attack prevention** — cache reads/writes check for symlinks
- **Atomic cache writes** — temp file + rename prevents corrupted cache entries
- **Path traversal protection** — validates all file paths and package names

### 📋 Flexible Policy Engine
- **Block / warn / allow** per severity level — configurable in `.pnpm-audit.yaml`
- **Allowlist** by CVE ID, GHSA ID, package name, version range — with optional expiration dates
- **Scoped allowlist entries** — match specific CVE + package + version combinations
- **Severity override** via `PNPM_AUDIT_BLOCK_SEVERITY` env var for CI flexibility

### 🔌 CI/CD Native
- **GitHub Actions** — `::error::` / `::warning::` annotations, outputs via `$GITHUB_OUTPUT`, auto-detected
- **Azure DevOps** — `##[group]`, `##[error]`, `##vso[task.setvariable]` commands, auto-detected
- **JSON output** — structured output for custom CI parsing
- **Human-readable** — colored terminal output with progress bars for local development
- **Auto-verbose in CI** — detects `CI`, `GITHUB_ACTIONS`, `TF_BUILD`, `GITLAB_CI`, `JENKINS_URL`

### 📦 Offline & Air-Gap Support
- **Bundled static DB** works without internet — historical vulns checked locally
- **`--offline` mode** — disables all API calls, relies on static DB + cache only
- **Cache survives across installs** — once fetched, results are reused until TTL expires

### 📊 Compact Status Banner
- **Always visible** — every `pnpm install` shows a one-line banner confirming the hook is active
- **Clean installs** — single line: package count, source status, "✅ clean", duration
- **Warnings** — banner expands with up to 5 CVE IDs, severity, package name, and title
- **Blocked installs** — banner shows all blocked CVEs with fix versions, followed by the full detailed report
- **Non-intrusive** — clean installs produce just one line of output; no visual noise

### 🛠️ Developer Experience
- **Zero config** — install, setup, done. Sensible defaults block critical + high.
- **CLI scanner** — `pnpm-audit-scan` for manual audits without installing
- **`--update-db`** — update the bundled vulnerability database from CLI
- **Custom config** — `.pnpm-audit.yaml` for per-project security policies
- **Private registry support** — works with custom npm registries via `PNPM_REGISTRY`
- **Temporary disable** — `pnpm install --ignore-pnpmfile` or rename `.pnpmfile.cjs`

## Quick Start

```bash
pnpm add -D pnpm-audit-hook && pnpm exec pnpm-audit-setup
```

Done! Every `pnpm install` will now audit packages before downloading.

## Quick How-To

### Enable/Disable Vulnerability Sources

```yaml
# .pnpm-audit.yaml
sources:
  github: true    # GitHub Advisory Database (default: true)
  osv: true       # OSV.dev — aggregates GHSA + npm + more (default: true)
  nvd: true       # NVD severity enrichment only (default: true)
```

Or via environment variables:
```bash
PNPM_AUDIT_DISABLE_GITHUB=true pnpm install   # Skip GitHub Advisory
PNPM_AUDIT_DISABLE_OSV=true pnpm install       # Skip OSV.dev
```

### Run an Offline Audit (No Network)

```bash
# Use only the bundled static database
pnpm-audit-scan --offline

# Or set the environment variable
PNPM_AUDIT_OFFLINE=true pnpm install
```

### Update the Vulnerability Database

```bash
# Quick incremental update (recommended)
pnpm-audit-scan --update-db

# Full rebuild from scratch
pnpm-audit-scan --update-db=full

# Or via npm scripts (equivalent)
GITHUB_TOKEN=your_token pnpm run update-vuln-db:incremental
```

### Scan Without Installing

```bash
# Run audit manually on current lockfile
pnpm-audit-scan

# Output as JSON for CI parsing
pnpm-audit-scan --format json

# Only block on critical vulnerabilities
pnpm-audit-scan --severity critical
```

### Allowlist a Known Vulnerability

```yaml
# .pnpm-audit.yaml
policy:
  allowlist:
    - id: CVE-2024-12345
      reason: "False positive — we don't use the affected API"
      expires: "2025-12-31"
```

## How It Works

### Overview

```mermaid
flowchart LR
    A[pnpm install] --> B[Resolve Dependencies]
    B --> C[.pnpmfile.cjs Hook]
    C --> D{Audit Packages}
    D -->|Safe| E[Download & Install]
    D -->|Vulnerable| F[Block Install]
```

When you run `pnpm install`, the hook intercepts the process **after dependency resolution but before downloading**. This means vulnerable packages are blocked without ever being downloaded to your machine.

### Detailed Flow

```mermaid
flowchart TD
    subgraph PNPM["pnpm install"]
        A[Start] --> B[Resolve dependency graph]
        B --> C[Generate lockfile]
    end

    subgraph HOOK["pnpm-audit-hook"]
        C --> D[".pnpmfile.cjs<br/>afterAllResolved()"]
        D --> E[Extract packages from lockfile]
        E --> F[Load config from .pnpm-audit.yaml]
        F --> G{Check cache}
        G -->|Cache hit| H[Use cached results]
        G -->|Cache miss| I[Query vulnerability sources]

        subgraph SOURCES["Vulnerability Sources"]
            I --> J[Static DB<br/>Historical vulns]
            I --> K[GitHub Advisory API<br/>Recent vulns]
            I --> K2[OSV.dev API<br/>Aggregated vulns]
            J --> L[Merge & deduplicate]
            K --> L
            K2 --> L
            L --> M{Unknown severity?}
            M -->|Yes| N[Enrich from NVD]
            M -->|No| O[Continue]
            N --> O
        end

        H --> P[Apply policy rules]
        O --> P
        P --> Q{Check allowlist}
        Q -->|Allowed| R[Skip]
        Q -->|Not allowed| S{Severity check}
        S -->|critical/high| T[BLOCK]
        S -->|medium/low| U[WARN]
        S -->|unknown| U
    end

    subgraph RESULT["Result"]
        T --> V[Throw error<br/>Abort install]
        U --> W[Log warnings]
        R --> W
        W --> X[Continue install]
        X --> Y[Download packages]
    end
```

### Installation Changes

When you run `pnpm exec pnpm-audit-setup`, these files are created in your project:

| File | Purpose |
|------|---------|
| `.pnpmfile.cjs` | pnpm hook entry point - intercepts `pnpm install` |
| `.pnpm-audit.yaml` | Optional configuration file (created if missing) |
| `.pnpm-audit-cache/` | Cache directory (created automatically at runtime) |

### File Structure After Installation

```
your-project/
├── .pnpmfile.cjs          # Hook that pnpm loads automatically
├── .pnpm-audit.yaml       # Your security policy config (optional)
├── .pnpm-audit-cache/     # Cached vulnerability data (auto-created)
├── node_modules/
│   └── pnpm-audit-hook/   # The installed package
│       ├── dist/          # Compiled audit logic
│       └── .pnpmfile.cjs  # Template hook file
├── package.json
└── pnpm-lock.yaml
```

## Vulnerability Sources

```mermaid
flowchart TD
    subgraph PRIMARY["Primary Sources (queried in parallel)"]
        A[Static Database] --> D[Merged Results]
        B[GitHub Advisory API] --> D
        C[OSV.dev API] --> D
    end

    subgraph ENRICHMENT["Severity Enrichment"]
        D --> E{Severity = unknown?}
        E -->|Yes| F[Query NVD API]
        E -->|No| G[Final Results]
        F --> G
    end

    style A fill:#90EE90
    style B fill:#87CEEB
    style C fill:#DDA0DD
    style F fill:#FFE4B5
```

| Source | Type | Description | Rate Limits |
|--------|------|-------------|-------------|
| **Static DB** | Bundled | Historical vulnerabilities (2020-2025), works offline, gzip-compressed with integrity hashes | None |
| **GitHub Advisory** | API | Real-time vulnerability data from GHSA | 60/hr (no token), 5000/hr (with token) |
| **OSV.dev** | API | Aggregated vulnerabilities from multiple databases (GHSA, npm, etc.). Free, no auth required | Generous (no key needed) |
| **NVD** | API | Severity enrichment only (CVSS scores) | 5/30s (no key), 50/30s (with key) |

### Query Strategy

```mermaid
sequenceDiagram
    participant H as Hook
    participant C as Cache
    participant S as Static DB
    participant G as GitHub API
    participant O as OSV.dev API
    participant N as NVD API

    H->>C: Check cache for package@version
    alt Cache hit (not expired)
        C-->>H: Return cached vulnerabilities
    else Cache miss
        H->>S: Query historical vulns (before cutoff)
        S-->>H: Historical findings
        par Query live sources in parallel
            H->>G: Query recent vulns (after cutoff)
            G-->>H: GitHub findings
        and
            H->>O: Query all known vulns
            O-->>H: OSV findings
        end
        H->>H: Merge & deduplicate

        opt Has unknown severity
            H->>N: Enrich severity data
            N-->>H: CVSS scores
        end

        H->>C: Cache results (TTL based on severity)
    end
```

## Blocking Policy

### Default Policy

```yaml
policy:
  block:    # Abort install if found
    - critical
    - high
  warn:     # Log warning but continue
    - medium
    - low
    - unknown
```

### Policy Decision Flow

```mermaid
flowchart TD
    A[Vulnerability Found] --> B{In allowlist?}
    B -->|Yes, not expired| C[ALLOW - Skip]
    B -->|No or expired| D{Severity level?}

    D -->|critical| E[BLOCK]
    D -->|high| E
    D -->|medium| F[WARN]
    D -->|low| F
    D -->|unknown| F

    E --> G[Collect all blocks]
    F --> H[Collect all warnings]
    C --> I[Continue]

    G --> J{Any blocks?}
    J -->|Yes| K[Throw Error<br/>Abort pnpm install]
    J -->|No| L[Log warnings]
    H --> L
    L --> M[Continue install]

    style E fill:#FF6B6B
    style F fill:#FFE66D
    style C fill:#90EE90
    style K fill:#FF6B6B
```

### Severity Levels

| Severity | CVSS Score | Default Action | Example |
|----------|------------|----------------|---------|
| **critical** | 9.0 - 10.0 | Block | Remote code execution |
| **high** | 7.0 - 8.9 | Block | Authentication bypass |
| **medium** | 4.0 - 6.9 | Warn | Information disclosure |
| **low** | 0.1 - 3.9 | Warn | Minor information leak |
| **unknown** | N/A | Warn | Severity not determined |

## Prerequisites

- **Node.js** ≥ 18
- **pnpm** (any version that supports `.pnpmfile.cjs` — pnpm 6+)

> **Note**: This tool is designed for pnpm only. For npm projects, use `npm audit`. For yarn, use `yarn audit`.

## Installation

### Per-Project (Recommended)

```bash
# Step 1: Install as a dev dependency
pnpm add -D pnpm-audit-hook

# Step 2: Run the setup script to create the hook file
pnpm exec pnpm-audit-setup
```

**What this does:**
1. Installs the package into `node_modules/`
2. Creates `.pnpmfile.cjs` in your project root — this is the hook that pnpm loads automatically
3. Creates `.pnpm-audit.yaml` — your security policy config (optional, sensible defaults applied)

**Files to commit:**
```bash
git add .pnpmfile.cjs .pnpm-audit.yaml
echo ".pnpm-audit-cache/" >> .gitignore
git add .gitignore
```

### Global (All Projects)

Enable vulnerability auditing for every pnpm project on your machine:

```bash
# 1. Install globally
pnpm add -g pnpm-audit-hook

# 2. Create global hooks directory and copy files
mkdir -p ~/.pnpm-hooks
cp $(pnpm root -g)/pnpm-audit-hook/dist ~/.pnpm-hooks/ -r
cp $(pnpm root -g)/pnpm-audit-hook/.pnpmfile.cjs ~/.pnpm-hooks/

# 3. Tell pnpm to use the global hook
pnpm config set global-pnpmfile ~/.pnpm-hooks/.pnpmfile.cjs
```

### From Source

```bash
git clone https://github.com/asx8678/pnpm-audit-hook.git
cd pnpm-audit-hook
pnpm install && pnpm run build

# Copy to your project
cp -r dist /path/to/your/project/
cp .pnpmfile.cjs /path/to/your/project/
```

### Upgrading from v1.1.0

If upgrading from v1.1.0, note these changes:
- **OSV.dev is now enabled by default** — adds a new vulnerability source alongside GitHub Advisory. To disable: set `sources.osv: false` in `.pnpm-audit.yaml` or `PNPM_AUDIT_DISABLE_OSV=true`
- **Cache keys changed** — a one-time cache rebuild will happen automatically (no action needed)
- **More vulnerabilities may be found** — OSV.dev aggregates GHSA + npm + other databases, so previously-clean installs may now report new findings
- **`--update-db` requires source checkout** — the CLI `--update-db` flag runs `scripts/update-vuln-db.ts` which is only available when developing from source, not from an `npm install`'d copy. Use `pnpm run update-vuln-db:incremental` from the cloned repo instead.

## Verify Installation

```bash
# ✅ This should succeed (safe package)
pnpm add lodash

# 🚫 This should be BLOCKED (known vulnerable version)
pnpm add event-stream@3.3.6
```

When a vulnerability is blocked, you'll see the compact banner followed by the full report:

```
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

When there are warnings (medium/low severity), you see the banner with CVE details but install continues:

```
🛡️  pnpm-audit ── 87 packages ── github ✓  osv ✓  static-db ✓ ── ⚠️  2 warnings (1 medium, 1 low) ── 312ms
  ⚠  CVE-2024-4067 [MEDIUM] micromatch@4.0.5 — ReDoS vulnerability
  ⚠  CVE-2024-4068 [MEDIUM] braces@3.0.2 — Uncontrolled resource consumption
```

When everything is clean — just a single line:

```
🛡️  pnpm-audit ── 142 packages ── github ✓  osv ✓  static-db ✓ ── ✅ clean ── 203ms
```

## Usage

### Automatic Mode (Default)

Once installed, auditing happens automatically on every `pnpm install`:

```bash
pnpm install                    # Audit runs automatically
pnpm add express                # Single package is audited too
pnpm add lodash@4.17.21        # Safe version — installs normally
pnpm add event-stream@3.3.6    # Vulnerable — blocked before download
```

No extra commands needed. The hook intercepts pnpm's dependency resolution and blocks vulnerable packages **before they're downloaded**.

### Manual Scan

Run an audit against your current lockfile without installing anything:

```bash
pnpm-audit-scan                       # Human-readable output
pnpm-audit-scan --format json         # JSON output (for CI parsing)
pnpm-audit-scan --severity critical   # Only block critical vulns
pnpm-audit-scan --offline             # Static DB only, no network
```

### Output Formats

| Format | Use Case | Flag |
|--------|----------|------|
| `human` | Terminal, local development | `--format human` (default) |
| `json` | CI parsing, scripting | `--format json` |
| `github` | GitHub Actions annotations | `--format github` (auto-detected) |
| `azure` | Azure DevOps pipeline | `--format azure` (auto-detected) |

### What Happens When Vulnerabilities Are Found

| Severity | Default Action | What You See |
|----------|---------------|--------------|
| **critical** / **high** | **Block** | Install fails with error details, exit code 1 |
| **medium** / **low** | **Warn** | Warning logged, install continues, exit code 2 |
| **unknown** | **Warn** | Warning logged, NVD enrichment attempted |

### Common Workflows

**Accept a specific vulnerability temporarily:**
```yaml
# .pnpm-audit.yaml
policy:
  allowlist:
    - id: CVE-2024-12345
      reason: "Accepted risk — patching next sprint"
      expires: "2025-06-01"
```

**Block only critical vulnerabilities in CI:**
```bash
pnpm-audit-scan --severity critical
```

**Run in offline/air-gapped environments:**
```bash
PNPM_AUDIT_OFFLINE=true pnpm install
```

**Update the bundled vulnerability database:**
```bash
pnpm-audit-scan --update-db          # Incremental (fast)
pnpm-audit-scan --update-db=full     # Full rebuild (slower, needs GITHUB_TOKEN)
```

## Uninstall

### Per-Project

```bash
# 1. Remove the hook file (required — this is what activates the hook)
rm .pnpmfile.cjs

# 2. Remove the package
pnpm remove pnpm-audit-hook

# 3. Clean up config and cache (optional)
rm -f .pnpm-audit.yaml
rm -rf .pnpm-audit-cache/
```

> **Tip**: Removing just `.pnpmfile.cjs` is enough to fully disable the hook. The package can stay installed without any effect.

### Global

```bash
# 1. Remove the global hook config
pnpm config delete global-pnpmfile

# 2. Remove the hook files
rm -rf ~/.pnpm-hooks

# 3. Remove the global package
pnpm remove -g pnpm-audit-hook
```

### Temporarily Disable (Without Uninstalling)

```bash
# Rename the hook file to disable it temporarily
mv .pnpmfile.cjs .pnpmfile.cjs.disabled

# Re-enable later
mv .pnpmfile.cjs.disabled .pnpmfile.cjs
```

Or skip the audit for a single install:

```bash
# Use --ignore-pnpmfile to bypass the hook for one command
pnpm install --ignore-pnpmfile
```

## Configuration

Create `.pnpm-audit.yaml` in your project root:

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

# Fail-closed security options (defaults are secure)
failOnNoSources: true       # Block if all sources disabled
failOnSourceError: true      # Block if a source fails
offline: false               # Set true for air-gapped environments
```

All fields are optional. Defaults are applied for missing values.

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `policy.block` | Severities that abort install | `["critical", "high"]` |
| `policy.warn` | Severities that log warnings | `["medium", "low", "unknown"]` |
| `policy.allowlist` | Exceptions to skip | `[]` |
| `sources.github` | Enable GitHub Advisory | `true` |
| `sources.osv` | Enable OSV.dev source | `true` |
| `sources.nvd` | Enable NVD enrichment | `true` |
| `performance.timeoutMs` | API timeout (1-300,000) | `15000` |
| `cache.ttlSeconds` | Cache duration (1-86,400) | `3600` |
| `staticBaseline.enabled` | Use bundled vuln database | `true` |
| `staticBaseline.cutoffDate` | Static DB coverage date | `2025-12-31` |
| `staticBaseline.dataPath` | Custom path to static DB data directory | Auto-detected |
| `failOnNoSources` | Block install when all sources disabled | `true` |
| `failOnSourceError` | Block install when a source fails | `true` |
| `offline` | Skip all API calls, use only static DB + cache | `false` |

## Allowlist

Suppress specific vulnerabilities or packages:

```yaml
policy:
  allowlist:
    # By CVE/GHSA ID
    - id: CVE-2024-12345
      reason: "False positive for our use case"

    # By package name
    - package: legacy-lib
      reason: "Accepted risk"
      expires: "2025-06-01"

    # Scoped: specific CVE in specific package
    - id: CVE-2024-12345
      package: affected-pkg
      version: ">=1.0.0 <2.0.0"  # Optional version constraint
      reason: "Only affects unused feature"
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | One of id/package | CVE or GHSA identifier (case-insensitive) |
| `package` | One of id/package | Package name to ignore (case-insensitive) |
| `version` | No | Semver range constraint |
| `reason` | No | Audit trail documentation |
| `expires` | No | ISO date when entry expires |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` / `GH_TOKEN` | GitHub API token (higher rate limits) |
| `NVD_API_KEY` / `NIST_NVD_API_KEY` | NVD API key (higher rate limits) |
| `PNPM_AUDIT_CONFIG_PATH` | Custom config file location |
| `PNPM_AUDIT_DISABLE_GITHUB` | Disable GitHub Advisory source |
| `PNPM_AUDIT_DISABLE_OSV` | Disable OSV.dev source |
| `PNPM_AUDIT_BLOCK_SEVERITY` | Override block severities (comma-separated, e.g. `critical,high,medium`) |
| `PNPM_AUDIT_QUIET` | Suppress info/warn output |
| `PNPM_AUDIT_DEBUG` | Enable debug logging |
| `PNPM_AUDIT_VERBOSE` | Enable verbose logging |
| _(auto-detected)_ | Verbose mode auto-enables in CI: `CI`, `GITHUB_ACTIONS`, `TF_BUILD`, `GITLAB_CI`, `JENKINS_URL` |
| `PNPM_AUDIT_JSON` | JSON output format |
| `PNPM_AUDIT_FORMAT` | Output format (`human`, `azure`, `github`, `json`) |
| `PNPM_AUDIT_OFFLINE` | Use only static baseline DB (no network) |
| `PNPM_AUDIT_FAIL_ON_NO_SOURCES` | Fail if no advisory sources available (default: `true`) |
| `PNPM_AUDIT_FAIL_ON_SOURCE_ERROR` | Fail if an advisory source errors (default: `true`) |
| `PNPM_AUDIT_GITHUB_CONCURRENCY` | Max concurrent GitHub API requests (default: `10` with token, `3` without) |
| `PNPM_REGISTRY` / `npm_config_registry` | Custom npm registry URL (default: `https://registry.npmjs.org/`) |

## CLI Reference

The `pnpm-audit-scan` CLI supports these flags:

| Flag | Description |
|------|-------------|
| `--format <format>` | Output format: `human`, `json`, `azure`, `github` (default: `human`) |
| `--severity <list>` | Comma-separated severity levels to block (default: `critical,high`) |
| `--offline` | Skip live API calls, use only static DB + cache |
| `--update-db` | Update vulnerability database (incremental) |
| `--update-db=full` | Update vulnerability database (full rebuild) |
| `--quiet` | Suppress non-error output |
| `--verbose` | Enable verbose output |
| `--debug` | Enable debug output |
| `--config <path>` | Path to `.pnpm-audit.yaml` config file |
| `--help` | Show help text |
| `--version` | Show version |

When `--update-db` is passed, the DB update runs and the CLI exits (no audit is performed).

## Caching

```mermaid
flowchart LR
    A[Package Query] --> B{Cache exists?}
    B -->|Yes| C{Expired?}
    C -->|No| D[Return cached]
    C -->|Yes| E[Query APIs]
    B -->|No| E
    E --> F[Cache with TTL]
    F --> G[Return results]

    style D fill:#90EE90
```

### Cache Location

```
.pnpm-audit-cache/
├── ab/
│   └── ab1234...def.json    # Cached by SHA256 hash
├── cd/
│   └── cd5678...ghi.json
└── ...
```

### Dynamic TTL

Cache duration varies by severity to balance freshness and performance:

| Severity | TTL | Reason |
|----------|-----|--------|
| Critical | 15 min | Need fast response for active threats |
| High | 30 min | Important but less urgent |
| Medium | 1 hour | Standard caching |
| Low/Unknown | Config TTL | Use configured default |

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

The hook runs automatically during `pnpm install` and will fail the job if blocking vulnerabilities are found.

The GitHub Actions format emits `::error::` / `::warning::` annotations for findings and sets outputs via `$GITHUB_OUTPUT` for downstream steps:

| Output | Description |
|--------|-------------|
| `audit-blocked` | `true` if install is blocked |
| `vulnerability-count` | Total number of vulnerabilities |
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
    displayName: 'Install with Audit'
    env:
      GITHUB_TOKEN: $(GITHUB_TOKEN)
      NVD_API_KEY: $(NVD_API_KEY)
      PNPM_AUDIT_FORMAT: azure
```

The Azure DevOps format uses `##[group]`, `##[error]`, `##[warning]`, and `##vso[task.setvariable]` logging commands for pipeline annotations and variables. It is also auto-detected when running in Azure Pipelines (`TF_BUILD=True`).

| Variable | Description |
|----------|-------------|
| `AUDIT_BLOCKED` | `true` if install is blocked |
| `AUDIT_VULNERABILITY_COUNT` | Total number of vulnerabilities |
| `AUDIT_CRITICAL_COUNT` | Number of critical vulnerabilities |
| `AUDIT_HIGH_COUNT` | Number of high vulnerabilities |

## Static Vulnerability Database

The hook includes a bundled database of historical vulnerabilities (2020-2025) that enables faster audits and reduced API calls.

### Benefits

- **Faster audits**: No API calls needed for known historical vulnerabilities
- **Offline capability**: Historical vulnerability checks work without internet
- **Rate limit friendly**: Minimizes API usage
- **Reliable**: Not affected by API outages for historical data

### Database Integrity

The static database includes SHA-256 integrity hashes for all vulnerability shard files, computed at build time and embedded in the index. This protects against tampering — if a shard file in `node_modules` is modified to suppress known vulnerabilities, the integrity check will detect it.

- Hashes are computed during `pnpm run build` by the optimizer
- Stored in the compressed index alongside package metadata
- Verified transparently at load time by the reader

### Database Compression

The static database is automatically optimized during the build process:

- **Index optimization**: Field names are compacted (e.g., `schemaVersion` → `ver`, `packages` → `p`) reducing index size by ~80%
- **Gzip compression**: Shard files larger than 10 KB are gzip-compressed (`.json.gz`), reducing the npm tarball by ~3-5x
- **Transparent reading**: The reader handles both `.json.gz` and `.json` formats automatically — no configuration needed

The optimization runs automatically during `pnpm run build` via `scripts/optimize-static-db.js`.

For a detailed evaluation of database packaging alternatives (separate npm package, CDN fetch, etc.), see [docs/db-packaging-evaluation.md](docs/db-packaging-evaluation.md).

### Updating the Database

The bundled static database is built from the [GitHub Advisory Database](https://github.com/advisories) using a GraphQL API query. The update script (`scripts/update-vuln-db.ts`) fetches all npm security advisories, filters for the NPM ecosystem, and writes one JSON shard file per affected package.

#### How `update-vuln-db.ts` Works

```mermaid
flowchart TD
    A[Start] --> B{Mode?}
    B -->|--incremental| C[Load existing index.json]
    B -->|full rebuild| D[Start fresh]
    B -->|--sample| E[Load fixtures/sample-vulns.json]

    C --> F[Set updatedSince = index.lastUpdated]
    F --> G[Fetch advisories from GitHub GraphQL API]
    D --> G

    G --> H[Filter for NPM ecosystem]
    H --> I[Group vulnerabilities by package name]
    I --> J[Deduplicate by advisory ID]
    J --> K[Write shard files]

    E --> K

    K --> L["Save data/{name}.json per package"]
    L --> M[Build index.json with package metadata]
    M --> N[Done — run pnpm build to optimize + compress]

    style G fill:#87CEEB
    style E fill:#90EE90
```

**Step by step:**

1. **Fetch** — Queries GitHub's GraphQL API (`api.github.com/graphql`) in batches of 100 advisories, paginating through all results. Uses `updatedSince` for incremental mode.
2. **Filter** — Only keeps advisories with `ecosystem: NPM` vulnerabilities. Skips advisories published before the `--since` date if specified.
3. **Normalize** — Converts each advisory into the `StaticVulnerability` format: ID, severity, affected version range, fixed version, identifiers (CVE/GHSA), title, URL.
4. **Deduplicate** — Skips vulnerabilities already present (by ID) when doing incremental updates.
5. **Write shards** — Saves one JSON file per package (`data/lodash.json`, `data/@angular/core.json`, etc.)
6. **Build index** — Creates `index.json` with package counts, max severity, latest vulnerability date, and build metadata.

#### GitHub Token (Recommended but Optional)

| Scenario | Rate Limit | Speed |
|----------|-----------|-------|
| **Without `GITHUB_TOKEN`** | 60 requests/hr | ~6,000 advisories/hr — full rebuild takes hours |
| **With `GITHUB_TOKEN`** | 5,000 requests/hr | Full rebuild in minutes |

The token needs **no special scopes** — it only reads public advisory data. Any GitHub Personal Access Token works:

```bash
# Create a token at: https://github.com/settings/tokens
# No scopes needed — just click "Generate token"
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

If no token is set and the API rate-limits the script, it **automatically falls back to sample data** (50 popular packages with known vulns).

#### Update Commands

```bash
# Incremental update — only fetches advisories modified since last build (fast)
pnpm run update-vuln-db:incremental

# Full rebuild — fetches ALL npm advisories since 2021 (slow without token)
pnpm run update-vuln-db

# Full rebuild with no date filter (everything)
pnpm run update-vuln-db:full

# Sample data only — no API calls, uses bundled test fixtures
pnpm run update-vuln-db -- --sample

# Custom cutoff date
pnpm run update-vuln-db -- --cutoff=2024-06-30T23:59:59Z
```

Or via the CLI (runs the same script under the hood):
```bash
pnpm-audit-scan --update-db           # Incremental
pnpm-audit-scan --update-db=full      # Full rebuild
```

> **Note**: `--update-db` via CLI requires a source checkout with `tsx` installed. It won't work from an `npm install`'d copy of the package.

#### After Updating: Build & Commit

After the database is updated, you must **rebuild** to apply optimization and compression:

```bash
# 1. Rebuild (compiles TypeScript, copies DB, optimizes + compresses, bundles)
pnpm run build

# 2. Commit the updated data
git add src/static-db/data/ dist/static-db/data/
git commit -m "chore: update vulnerability database"
```

The build pipeline runs these steps automatically:
1. `tsc` — compile TypeScript
2. `copy-static-db.js` — copy `src/static-db/data/` → `dist/static-db/data/`
3. **`optimize-static-db.js`** — optimize index (compact keys), gzip-compress large shards, compute SHA-256 integrity hashes
4. `bundle.js` — bundle `dist/index.js` with esbuild (minified)

#### What Gets Written

```
src/static-db/data/
├── index.json              # Package index with counts, severity, build metadata
├── lodash.json             # Shard: 4 vulnerabilities for lodash
├── axios.json              # Shard: 2 vulnerabilities for axios
├── @angular/
│   └── core.json           # Scoped package shard
├── express.json
└── ... (one file per vulnerable package)
```

After `pnpm run build`, the `dist/` copy is optimized:
```
dist/static-db/data/
├── index.json.gz           # Optimized + compressed index (with integrity hashes)
├── lodash.json             # Small shards stay uncompressed
├── @angular/
│   └── core.json
├── directus.json.gz        # Large shards are gzip-compressed
└── ...
```

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

## Security Model

### Fail-Closed Design

The hook uses a **fail-closed** security model:

| Condition | Behavior |
|-----------|----------|
| API failure | Block install (configurable) |
| Invalid allowlist entry | Entry ignored (treated as not allowed) |
| Expired allowlist | Entry ignored |
| Unknown severity | Treated as "warn" (configurable) |
| Invalid semver in vuln data | Treated as potentially affected |

### Security Features

- **Pre-download blocking**: Vulnerable code never reaches your machine
- **No credential storage**: API keys only from environment variables
- **Path traversal protection**: Validates all file paths
- **Symlink attack prevention**: Detects symlinks in cache
- **Atomic cache writes**: Prevents partial/corrupted cache files
- **Database integrity verification**: SHA-256 hashes detect tampered vulnerability data
- **Cache key versioning**: DB updates automatically invalidate stale cached results

## Troubleshooting

### "AUDIT FAILED" — How do I unblock my install?

**Quick escape** (one-time bypass):
```bash
pnpm install --ignore-pnpmfile
```

**Investigate the issue:**
```bash
pnpm-audit-scan --format json | jq '.findings'
```

**Then choose one:**
1. **Upgrade** the vulnerable package to a patched version
2. **Allowlist** the CVE if it's a false positive (see [Allowlist](#allowlist))
3. **Lower severity threshold** — change `policy.block` in `.pnpm-audit.yaml`

### OSV.dev or GitHub API is unreachable (corporate proxy / air-gap)

```bash
# Option 1: Run in offline mode (uses bundled static DB only)
PNPM_AUDIT_OFFLINE=true pnpm install

# Option 2: Disable the failing source
PNPM_AUDIT_DISABLE_OSV=true pnpm install
PNPM_AUDIT_DISABLE_GITHUB=true pnpm install

# Option 3: Don't block on source errors
# In .pnpm-audit.yaml:
failOnSourceError: false
```

### Audit is slow

- **Set `GITHUB_TOKEN`** — without it, GitHub API is limited to 60 req/hr. With a token: 5,000 req/hr.
- **Check cache** — the `.pnpm-audit-cache/` directory caches results. If deleted, the next run re-fetches everything.
- **Use offline mode** for fastest audits: `pnpm-audit-scan --offline`

### Verbose logging is automatically enabled in CI — why?

The hook auto-detects CI environments and enables verbose output when any of these are set:
- `CI=true`
- `GITHUB_ACTIONS=true`
- `TF_BUILD=True` (Azure DevOps)
- `GITLAB_CI=true`
- `JENKINS_URL` is defined

To suppress this, set `PNPM_AUDIT_QUIET=true`.

### I updated the static DB but old results still show

Cache keys include the DB version, so caches are automatically invalidated when the DB changes. If you still see stale results:
```bash
rm -rf .pnpm-audit-cache/
pnpm install
```

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
pnpm add lodash              # Safe package
pnpm add event-stream@3.3.6  # Vulnerable - should be blocked
```

### Run Tests

```bash
pnpm test
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - no blocking vulnerabilities |
| 1 | Blocked - critical/high vulnerabilities found |
| 2 | Warnings - medium/low vulnerabilities found |
| 3 | Source error - API failure (fail-closed) |

## License

MIT
