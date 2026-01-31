# pnpm-audit-hook

A pnpm hook that audits dependencies for vulnerabilities **before packages are downloaded**. It queries 2 vulnerability databases in parallel and blocks installs when critical or high severity issues are found.

## Quick Start

1. Add the hook files to your repo root:
   - `.pnpmfile.cjs` - the pnpm hook entry point
   - `dist/` - compiled JavaScript (run `npm run build`)
   - `.pnpm-audit.yaml` - configuration (optional)

2. Run install:
   ```bash
   pnpm install
   ```

If blocking vulnerabilities are found, the install fails before any packages are downloaded.

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
  nvd: true

performance:
  timeoutMs: 15000

cache:
  ttlSeconds: 3600
```

All fields are optional. Set any source to `false` to disable it.

## Vulnerability Sources

| Source | Description | Auth |
|--------|-------------|------|
| **GitHub Advisory** | GitHub Security Advisory database (GHSA) | Optional |
| **NVD** | NIST National Vulnerability Database (enrichment data) | Optional |

## Allowlist

Suppress specific vulnerabilities or packages:

```yaml
policy:
  allowlist:
    - id: CVE-2024-12345
      reason: "False positive for our use case"
    - package: legacy-lib
      reason: "Accepted risk"
      expires: "2025-06-01"
```

- `id` - CVE or GHSA identifier to ignore
- `package` - Package name to ignore entirely
- `reason` - Why it's allowed (for audit trail)
- `expires` - ISO date when the allowlist entry expires

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PNPM_AUDIT_CONFIG_PATH` | Override config file location |
| `PNPM_AUDIT_DISABLE_GITHUB` | Disable GitHub Advisory source |
| `GITHUB_TOKEN` | GitHub API token (optional) |
| `NVD_API_KEY` | NVD API key (optional) |

## How It Works

1. pnpm resolves the full dependency graph
2. `.pnpmfile.cjs` hook runs `afterAllResolved()` before downloads
3. The hook queries all 2 vulnerability sources in parallel
4. Findings are deduplicated and checked against the severity policy
5. If any blocking vulnerabilities exist, pnpm aborts the install

**Note:** The `.pnpmfile.cjs` file must be in your workspace root directory.

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

## Build

```bash
npm ci
npm run build
```
