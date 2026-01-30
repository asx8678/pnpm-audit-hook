# pnpm-audit-hook — pre-download security audit for pnpm (Azure DevOps-ready)

This repository implements a **pnpm hook system** (via `.pnpmfile.cjs`) that performs a **multi-source security audit of the exact resolved dependency graph** **before** any package tarballs are downloaded.

It is designed for **enterprise** use cases:
- Azure DevOps pipelines (SARIF + PR comments + pipeline variables)
- Offline / air‑gapped operation (cache snapshot)
- Governance (allowlist with expiry + audit trail logs)

> **Important reality check:** pnpm hooks run from `.pnpmfile.cjs` in your repo. For the hook to run on a “first ever” install, the hook code must already be present locally (committed or vendored). This repo assumes you ship the hook code with your repo (or as a preinstalled agent tool) so it can execute **before downloads**.

---

## How it works

1. **pnpm resolves** the full dependency graph and produces an in-memory lockfile object.
2. `.pnpmfile.cjs` runs `afterAllResolved()` **before download**.
3. The hook:
   - extracts all resolved packages (direct + transitive) from the lockfile
   - queries multiple vulnerability sources **in parallel**
   - optionally enriches CVE scoring from NVD
   - performs integrity / (optional) signature checks
   - evaluates org security policy (.pnpm-audit.yaml + env overrides)
   - emits reports (SARIF/JUnit/HTML/JSON/SBOM) and an audit log
4. If policy says **block**, the hook throws — pnpm aborts before packages are fetched.

---

## Supported sources

Enabled by default:
- **OSV** (`https://api.osv.dev/v1/querybatch`)
- **npm Advisory API** (`/-/npm/v1/security/advisories`) against your configured registry
- **GitHub Security Advisories** (`https://api.github.com/advisories`) *(rate-limited without `GITHUB_TOKEN`)*
- **NVD enrichment** (CVE scoring) (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`)

Optional (disabled by default):
- **Sonatype OSS Index** (`OSSINDEX_USERNAME` + `OSSINDEX_TOKEN` optional; can run unauthenticated but rate-limited)

---

## Files you care about

- `.pnpmfile.cjs` — pnpm hook entry point
- `.pnpm-audit.yaml` — default policy config (customize in your repo)
- `.pnpm-audit.schema.json` — schema for config validation
- `azure-pipelines-pnpm-audit.yml` and `azure-pipelines/templates/*` — pipeline templates
- `scripts/` — offline DB snapshot + cache warming + baseline generation

---

## Quick start (developer machine)

### 1) Put the hook in your repo
Copy these into the **root** of your target repo:
- `.pnpmfile.cjs`
- the built JS bundle for this project (see “Build & ship” below) or vendor the whole repo folder and adjust `.pnpmfile.cjs` require path.

### 2) Add config
Copy `.pnpm-audit.yaml` to your repo root and adjust policies.

### 3) Run install
```bash
pnpm install
```

Default behavior:
- **blocks** on `high` / `critical`
- **warns** on `medium` / `low`
- writes reports:
  - `.pnpm-audit-report.html`
  - `.pnpm-audit-report.sarif.json`
  - `.pnpm-audit-report.json`

---

## Build & ship the hook code (so it runs before downloads)

This repo uses TypeScript. You need compiled JS present where `.pnpmfile.cjs` can `require()` it.

### Option A (common in enterprises): commit `dist/` into your repo template
```bash
npm ci
npm run build
git add dist
```

Then `.pnpmfile.cjs` can load `./dist/src/index.js` directly.

### Option B: vendor this repo into your product repo
Put this project under `tools/pnpm-audit-hook/` and change `.pnpmfile.cjs` to:

```js
const { createPnpmHooks } = require('./tools/pnpm-audit-hook/dist/src/index.js');
module.exports = createPnpmHooks();
```

---

## Configuration

### `.pnpm-audit.yaml` policy model (example)
```yaml
policies:
  block: [critical, high]
  warn: [medium, low]
  gracePeriod: 7
  unknownVulnData: warn       # warn|block|allow
  networkPolicy: fail-open    # fail-open|fail-closed

  allowlist:
    - cve: CVE-2023-XXXXX
      package: lodash
      expires: "2024-06-01"
      reason: "No exploit path in our usage"
      approvedBy: security-team

  blocklist:
    - event-stream
    - flatmap-stream

integrity:
  requireSha512Integrity: true
```

### Environment variable overrides

| Variable | Meaning |
|---|---|
| `PNPM_AUDIT_ENABLED` | `true/false` |
| `PNPM_AUDIT_SEVERITY_THRESHOLD` | `critical|high|medium|low` (auto-computes `block`/`warn`) |
| `PNPM_AUDIT_FAIL_ON_WARN` | `true/false` |
| `PNPM_AUDIT_OFFLINE_MODE` | `true/false` |
| `PNPM_AUDIT_OFFLINE_DB_PATH` | Path to a **read-only cache snapshot** for air‑gapped installs |
| `PNPM_AUDIT_NETWORK_POLICY` | `fail-open` / `fail-closed` |
| `PNPM_AUDIT_CACHE_TTL` | seconds |
| `PNPM_AUDIT_REPORT_FORMAT` | comma-separated: `json,sarif,html,junit,markdown,sbom-cyclonedx,sbom-spdx` |
| `PNPM_AUDIT_OUTPUT_DIR` | report output directory |
| `PNPM_AUDIT_BASENAME` | report base filename |
| `NVD_API_KEY` | NVD API key (optional but recommended for rate limits) |
| `GITHUB_TOKEN` | GitHub API token (recommended) |

### Emergency bypass (with audit trail)
```bash
PNPM_AUDIT_BYPASS=true PNPM_AUDIT_BYPASS_TOKEN=... PNPM_AUDIT_BYPASS_EXPECTED_TOKEN=... PNPM_AUDIT_BYPASS_REASON="Critical hotfix - remediation in progress" pnpm install
```

The bypass is recorded in `.pnpm-audit-log.ndjson` (append-only).

---

## Azure DevOps integration

### Use pipeline templates
Use the provided template `azure-pipelines-pnpm-audit.yml`:

```yaml
stages:
  - template: azure-pipelines-pnpm-audit.yml
    parameters:
      mode: 'pr'   # pr|ci|release|scan
      nodeVersion: '18.x'
      pnpmVersion: '9.x'
```

### SARIF
The hook emits `.pnpm-audit-report.sarif.json`. Azure DevOps can surface SARIF in the Security tab via supported tooling or extensions.

### PR comments
Enable PR comments in `.pnpm-audit.yaml`:
```yaml
azureDevOps:
  prComment:
    enabled: true
```

Pipeline must expose `$(System.AccessToken)` to scripts.

---

## Offline / air‑gapped mode

### Create a cache snapshot (connected machine)
```bash
node dist/scripts/sync-offline-db.js
# outputs: pnpm-audit-offline-db/ (cache + manifest)
```

### Use it in the air‑gapped environment
```bash
PNPM_AUDIT_OFFLINE_MODE=true PNPM_AUDIT_OFFLINE_DB_PATH=/secure/pnpm-audit-offline-db PNPM_AUDIT_NETWORK_POLICY=fail-closed pnpm install
```

If a package is not present in the snapshot cache:
- policy `unknownVulnData` decides allow/warn/block
- `fail-closed` mode blocks if any enabled source is unavailable

---

## Monorepos / pnpm workspaces

The lockfile parser reads:
- `packages` (all resolved transitive packages)
- `importers` (workspace projects) to mark **direct dependencies** per importer path

This lets policy apply uniformly across monorepos. You can add future extensions for importer-specific overrides.

---

## Performance tips

- Set concurrency (defaults to 8):
  ```bash
  PNPM_AUDIT_CONCURRENCY=12 pnpm install
  ```
- Reduce timeouts for fast-fail:
  ```bash
  PNPM_AUDIT_TIMEOUT_MS=8000 pnpm install
  ```
- Warm cache on build agents:
  ```bash
  node dist/scripts/warm-cache.js
  ```

The cache TTL is automatically shortened when **critical/high** findings exist (heuristic) to keep incident response fresh.

---

## FAQ / Design decisions

### 1) How are version ranges matched against affected versions?
- OSV: uses `ranges[].type=SEMVER` and `introduced/fixed` events; we convert that into a semver range and apply `semver.satisfies()`.
- npm advisory API: uses `vulnerable_versions` string ranges (semver range).
- GitHub advisory API: uses `vulnerable_version_range`.

This repo uses the `semver` library and normalizes pnpm lockfile versions by stripping peer suffixes like `1.2.3(eslint@8.0.0)`.

### 2) How are transitive dependencies handled?
The hook audits **every resolved package in the lockfile**, not just top-level dependencies. That means transitive dependencies are checked automatically.

### 3) Packages with no vulnerability data: safe or unknown?
This is configurable via:
```yaml
policies:
  unknownVulnData: warn  # warn|block|allow
```
In `fail-closed` mode, enabled source outages block installs regardless.

### 4) Cache invalidation strategy for zero-days
- TTL is severity-aware (critical/high cached shorter)
- scheduled pipeline scans can refresh caches regularly
- you can wipe cache directory (`.pnpm-audit-cache/`) to force a refresh
- you can also ship a new offline cache snapshot during incident response

---

## Development

```bash
npm ci
npm test
npm run build
```

---

## Outputs

Default artifacts:
- `.pnpm-audit-report.json`
- `.pnpm-audit-report.html`
- `.pnpm-audit-report.sarif.json`
- `.pnpm-audit-report.junit.xml` (if enabled)
- `.pnpm-audit-report.sbom.cdx.json` / `.spdx.json` (if enabled)
- `.pnpm-audit-log.ndjson` (append-only audit trail)

---

## Limitations (intentional)

- **NVD is used as CVE enrichment**, not as a package-to-CVE discovery source. Mapping npm packages to CVEs via CPEs is noisy and risky.

