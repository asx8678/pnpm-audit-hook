# pnpm-audit-hook — minimal pre-download security audit for pnpm

This repo provides a **pnpm hook** (via `.pnpmfile.cjs`) that checks the fully resolved dependency graph **before any packages are downloaded**. It blocks installs that include compromised packages or serious vulnerabilities and warns on lower‑severity issues.

Core behavior (fixed):
- **Fail‑closed**: if any vulnerability source is unavailable or returns invalid data, the install is blocked.
- **Severity policy**: `critical/high` → block, `medium/low/unknown` → warn (configurable).
- **Integrity checks**: lockfile integrity must match registry metadata; non‑sha512 integrity is blocked when enabled.
- **Output**: a single JSON report file + concise console summary.

> pnpm only runs hooks that are already present locally. You must ship the compiled hook with your repo (or vendor this repo) so it can run **before downloads**.

---

## How it works

1. pnpm resolves the full dependency graph and builds an in‑memory lockfile.
2. `.pnpmfile.cjs` runs `afterAllResolved()` before downloads.
3. The hook:
   - extracts all resolved packages
   - queries **OSV** for vulnerabilities
   - verifies registry integrity for each package
   - applies the severity policy
4. If any blocking condition exists, pnpm aborts the install.

---

## Supported sources

- OSV (`https://api.osv.dev/v1/querybatch`)

---

## Quick start

1) Ensure the hook is in your repo root:
- `.pnpmfile.cjs`
- compiled JS under `dist/` (see Build)

2) Copy the config file:
- `.pnpm-audit.yaml`

3) Run install:
```bash
pnpm install
```

If blocking issues are found, the install fails before any download.

---

## Configuration (`.pnpm-audit.yaml`)

```yaml
version: 1

policy:
  block: [critical, high]
  warn: [medium, low, unknown]

sources:
  osv: { enabled: true }

integrity:
  requireSha512Integrity: true

performance:
  concurrency: 8
  timeoutMs: 15000

cache:
  ttlSeconds: 3600
  dir: ".pnpm-audit-cache"

reporting:
  outputDir: "."
  basename: ".pnpm-audit-report"
```

Notes:
- **Fail‑closed** is always enforced: any source failure blocks the install.
- Adjust severity thresholds as needed.

---

## Output

- `.pnpm-audit-report.json`
- Console summary: `Blocked`, `Warnings`, or `No findings`

---

## Build

```bash
npm ci
npm run build
```

This writes compiled JS to `dist/` which `.pnpmfile.cjs` loads.
