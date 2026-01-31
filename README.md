# pnpm-audit-hook

A pnpm hook that audits dependencies for vulnerabilities **before packages are downloaded**. It queries the GitHub Advisory Database for vulnerabilities and optionally enriches severity data from NVD, blocking installs when critical or high severity issues are found.

## Installation

### Option 1: Copy to Your Project (Recommended)

1. **Clone or download this repository:**
   ```bash
   git clone https://github.com/asx8678/pnpm-audit-hook.git
   cd pnpm-audit-hook
   ```

2. **Build the hook:**
   ```bash
   npm install
   npm run build
   ```

3. **Copy these files to your project root:**
   ```bash
   cp -r dist /path/to/your/project/
   cp .pnpmfile.cjs /path/to/your/project/
   cp .pnpm-audit.yaml /path/to/your/project/  # optional config
   ```

4. **Done!** Now run `pnpm install` in your project - the hook will automatically audit all packages.

### Option 2: Global Setup (All Projects)

To enable the hook for all pnpm projects on your machine:

1. **Build the hook** (same as above):
   ```bash
   git clone https://github.com/asx8678/pnpm-audit-hook.git
   cd pnpm-audit-hook
   npm install && npm run build
   ```

2. **Create a global hooks directory:**
   ```bash
   mkdir -p ~/.pnpm-hooks
   cp -r dist ~/.pnpm-hooks/
   cp .pnpmfile.cjs ~/.pnpm-hooks/
   cp .pnpm-audit.yaml ~/.pnpm-hooks/  # optional
   ```

3. **Configure pnpm to use global hooks:**
   ```bash
   pnpm config set global-pnpmfile ~/.pnpm-hooks/.pnpmfile.cjs
   ```

4. **Verify it's set:**
   ```bash
   pnpm config get global-pnpmfile
   # Should output: /Users/yourname/.pnpm-hooks/.pnpmfile.cjs
   ```

Now every `pnpm install` on your machine will run the security audit.

### Option 3: Per-Project via npm Package

```bash
# In your project
pnpm add -D pnpm-audit-hook

# Copy hook file to project root
cp node_modules/pnpm-audit-hook/.pnpmfile.cjs .
```

## What Files Are Needed?

| File | Required | Description |
|------|----------|-------------|
| `dist/` | ✅ Yes | Bundled hook code (self-contained, no node_modules needed) |
| `.pnpmfile.cjs` | ✅ Yes | pnpm hook entry point |
| `.pnpm-audit.yaml` | ❌ Optional | Configuration (uses sensible defaults) |

## Quick Test

After installation, test that it works:

```bash
cd your-project
pnpm add lodash  # Safe package - should install
pnpm add event-stream@3.3.6  # Vulnerable - should block
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

### Configuration Constraints

The following validation rules are applied to configuration values:

| Setting | Constraint | Default |
|---------|------------|---------|
| `performance.timeoutMs` | 1 to 300,000 ms (5 minutes max) | 15,000 |
| `cache.ttlSeconds` | 1 to 86,400 seconds (24 hours max) | 3,600 |
| `staticBaseline.cutoffDate` | Valid ISO date format, must not be in the future | 2025-12-31 |

Invalid values are silently replaced with defaults to ensure safe operation.

## Vulnerability Sources

| Source | Description | Auth |
|--------|-------------|------|
| **GitHub Advisory** | Primary source - GitHub Security Advisory database (GHSA) | Optional |
| **NVD** | Severity enrichment only - NIST National Vulnerability Database | Optional |

GitHub Advisory is the primary vulnerability source. NVD provides additional severity metadata but does not add new vulnerability entries.

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

- `id` - CVE or GHSA identifier to ignore (case-insensitive)
- `package` - Package name to ignore entirely (case-insensitive)
- If both `id` and `package` are set, **both must match** (scoped allowlist)
- `reason` - Why it's allowed (for audit trail)
- `expires` - ISO date when the allowlist entry expires

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PNPM_AUDIT_CONFIG_PATH` | Override config file location |
| `PNPM_AUDIT_DISABLE_GITHUB` | Disable GitHub Advisory source |
| `GITHUB_TOKEN` | GitHub API token (optional) |
| `GH_TOKEN` | Alternative to GITHUB_TOKEN |
| `NVD_API_KEY` | NVD API key (optional) |
| `NIST_NVD_API_KEY` | Alternative to NVD_API_KEY |
| `PNPM_AUDIT_QUIET` | Suppress info/warn output (`true` to enable) |
| `PNPM_AUDIT_DEBUG` | Enable debug logging (`true` to enable) |
| `PNPM_AUDIT_JSON` | Enable JSON output format (`true` to enable) |

## How It Works

1. pnpm resolves the full dependency graph
2. `.pnpmfile.cjs` hook runs `afterAllResolved()` before downloads
3. The hook queries GitHub Advisory (and optionally NVD for severity enrichment)
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

## Static Vulnerability Database

The hook includes a bundled database of historical vulnerabilities (2020-2025) that enables faster audits and reduced API calls.

### How It Works

- **Historical vulnerabilities** (before the cutoff date) are served from the bundled static database
- **New vulnerabilities** (after the cutoff date) are fetched from live APIs
- This hybrid approach provides offline capability for historical data while ensuring fresh data for recent disclosures

### Benefits

- **Faster audits**: No API calls needed for known historical vulnerabilities
- **Reduced API calls**: Only new vulnerabilities require network requests
- **Offline capability**: Historical vulnerability checks work without internet access
- **Rate limit friendly**: Minimizes API usage against GitHub and NVD

### Configuration

Enable or disable the static baseline in `.pnpm-audit.yaml`:

```yaml
staticBaseline:
  enabled: true
  cutoffDate: "2025-12-31"
  dataPath: "node_modules/pnpm-audit-hook/dist/static-db/data"  # optional custom path
```

- `enabled` - Whether to use the static database (default: `true`)
- `cutoffDate` - Vulnerabilities published before this date use the static database (must be valid ISO format, not in future)
- `dataPath` - Optional custom path to static data directory (default: bundled data)

### Updating the Database

Update the bundled vulnerability database monthly to capture new disclosures:

```bash
# Full rebuild of the vulnerability database
npm run update-vuln-db

# Incremental update (faster, adds only new vulnerabilities)
npm run update-vuln-db:incremental
```

After updating, rebuild and commit the changes:

```bash
npm run build
git add src/static-db/data/ dist/static-db/data/
git commit -m "chore: update vulnerability database"
```

### Update Workflow

1. Run `npm run update-vuln-db:incremental` monthly
2. Optionally extend `cutoffDate` in your config to include newer static data
3. Commit the updated `data/` directory to your repository

## Build

```bash
npm ci
npm run build
```
