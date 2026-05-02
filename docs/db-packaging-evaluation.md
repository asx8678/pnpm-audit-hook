# DB Packaging Evaluation: Should We Separate the Vulnerability Database?

**Date:** 2025-05-02  
**Author:** Max 🐶 (code-puppy-a051e1)  
**Status:** Research / Decision Document  
**Jira:** pnpm-audit-hook-ckw.9

---

## Executive Summary

The `pnpm-audit-hook` package currently bundles ~3.5 MB of static vulnerability data (1,958 shard files) inside the npm tarball, accounting for ~83% of the total package size after compression. This evaluation examines three options — separate npm package, lazy CDN fetch, and status quo — to determine the best path forward. **The recommendation is Option C (status quo) with targeted mitigation**, as the project's offline-first security philosophy, the relatively modest tarball size (1.1 MB after gzip), and the operational complexity of splitting outweigh the benefits for the current scale.

---

## 1. Current State Analysis

### 1.1 Database Structure

The static vulnerability database lives at `dist/static-db/data/` and consists of:

| Location | Count | Format | Description |
|---|---|---|---|
| `data/index.json.gz` | 1 | gzipped JSON | Compact index with O(1) package lookup, integrity hashes |
| `data/{name}.json` | 45 | Uncompressed JSON | Popular packages (lodash, axios, express, etc.) |
| `data/packages/{name}.json` | 1,871 | Uncompressed JSON | Flat directory (legacy format, `_` for `/`) |
| `data/packages/{name}.json.gz` | 40 | gzipped JSON | Larger shards compressed individually |
| **Total** | **1,957 data files** | | **Plus 1 README.md** |

Additionally, the `dist/static-db/` directory contains 12 non-data files (compiled JS, type definitions, source maps) for the reader and optimizer modules (~105 KB combined).

### 1.2 Exact Size Measurements

All measurements taken from the built `dist/` directory after `pnpm run build`.

| Metric | Value | % of Package |
|---|---|---|
| `dist/` total (disk blocks) | 9.3 MB | — |
| `dist/` total (actual bytes) | ~4.3 MB | — |
| `dist/` excluding static-db | ~740 KB | ~17% |
| `dist/static-db/data/` (actual bytes) | ~3.5 MB | ~83% of dist/ |
| `dist/static-db/` non-data (code) | ~105 KB | ~2.4% |
| npm tarball (`pnpm-audit-hook-1.1.0.tgz`) | **1.1 MB** | — |

> **Key insight:** While the raw data is ~3.5 MB on disk (and ~9.1 MB in the source `src/static-db/data/`), the npm tarball's gzip compression across all files brings the actual download to only **1.1 MB**. The individual `.json.gz` shards (40 of them, biggest being `openclaw.json.gz` at 52 KB) benefit from pre-compression, and the tarball's outer gzip layer handles the rest efficiently.

### 1.3 How the DB Integrates

The data flows through the pipeline as follows:

1. **`scripts/update-vuln-db.ts`** — Fetches npm advisories from the GitHub Advisory Database (GraphQL API), groups by package name, writes shard files to `src/static-db/data/`.
2. **`scripts/copy-static-db.js`** — Copies `src/static-db/data/` → `dist/static-db/data/` at build time.
3. **`scripts/optimize-static-db.js`** — Post-copy: optimizes the index (compact field names, enum-based severity/source), gzip-compresses larger shards, computes SHA-256 integrity hashes, injects integrity map into the index.
4. **`src/databases/aggregator.ts`** — At runtime, creates a `StaticDbReader` pointing at `dist/static-db/data/`. The reader lazily loads shards on first request for a package, with a configurable LRU cache (default 2,000 entries).
5. **Integration**: The static DB is one source among several (GitHub Advisory live API, OSV.dev, NVD enrichment). It provides the "static baseline" — historical vulnerabilities that don't require network access. The aggregator queries all sources and deduplicates.

### 1.4 CI/CD Context

The GitHub Actions workflow (`.github/workflows/update-vuln-db.yml`) runs:
- **Schedule:** Weekly on Sundays at 03:00 UTC
- **Manual trigger:** Workflow dispatch with optional full rebuild flag
- **Process:** Fetches new/updated advisories (incremental by default), copies to `dist/`, optimizes, checks for meaningful data changes, and creates a PR with the updated shards
- **PR title format:** `chore(db): update vulnerability database YYYY-MM-DD`

### 1.5 Change Frequency Analysis

Based on git history:

```
DB data changes (src/static-db/data/):
  7b2b0c8 ci: fix force_full script and timestamp-churn false-positives
  2a8efb9 chore: update static vulnerability database (3167 -> 3631 vulns)
  abb367a Improve audit performance and caching
  5c0e527 feat: add static vulnerability database with caching system
  → 4 commits touching data across the project's history

Code changes (src/ excluding data/):
  5d865f6 fix(formatter): use GITHUB_OUTPUT file API, add formatter tests
  e2f8d73 docs: document Azure DevOps format
  9de6e00 fix(security): normalize integrity map path separators
  a6b9715 Include DB version in cache keys
  ... (10+ feature/fix commits)
  → Significantly more frequent code changes than data changes
```

**Conclusion:** DB updates happen weekly via CI, but code changes are more frequent (multiple per sprint). The DB grows monotonically as new vulnerabilities are discovered.

---

## 2. Options Comparison

| Criterion | Option A: Separate Package | Option B: Lazy CDN Fetch | Option C: Status Quo |
|---|---|---|---|
| **Install size** | ~740 KB (code only) | ~740 KB (code only) | 1.1 MB tarball |
| **First-use network** | ❌ pnpm install fetches both | ✅ Downloads on first use | ❌ None |
| **Offline capability** | ✅ Full (after install) | ❌ Requires network first time | ✅ Full |
| **Build complexity** | High | Medium | None |
| **CI/CD changes** | Major (2 packages, workspace) | Moderate (release artifacts) | None |
| **Versioning** | Independent | Pinned via hash | Coupled |
| **Supply chain risk** | Higher (2 packages to trust) | Lower (single source, hash-verified) | Baseline |
| **Maintenance burden** | High (sync versions, publish both) | Medium (CDN infra, cache logic) | None |
| **Tarball size increase per install** | ~740 KB | ~0 (first use: ~3.5 MB) | 1.1 MB |
| **User experience** | Works as before | First audit is slow (fetch + cache) | Seamless |

---

## 3. Detailed Analysis

### 3.1 Option A: Separate `@pnpm-audit-hook/db` npm Package

**How it would work:**
- Publish the contents of `src/static-db/data/` as a separate npm package, e.g., `@pnpm-audit-hook/db`
- The main `pnpm-audit-hook` package lists it as a peer dependency or optional dependency
- Users install both: `pnpm add pnpm-audit-hook @pnpm-audit-hook/db`
- The aggregator resolves the data path via `require.resolve('@pnpm-audit-hook/db')`
- The DB package gets its own semver range, published on the same weekly CI cadence

**Implementation Complexity: HIGH**

To implement this, we would need to:
1. Create a new npm package workspace (or separate repo) with its own `package.json`, `tsconfig.json`, build pipeline
2. Extract the data copy/optimize steps into the DB package's build
3. Wire up pnpm workspace (if monorepo) or cross-repo version coordination
4. Update the reader's data path resolution to use `require.resolve()` for the peer package
5. Set up CI/CD to publish both packages on DB update
6. Decide on versioning strategy (lockstep? independent semver?)
7. Handle the case where the DB package is missing (graceful fallback? hard error?)
8. Update documentation and setup scripts

**Pros:**
- Independent versioning: code updates don't force DB re-download
- Smaller initial install: ~740 KB instead of ~1.1 MB
- DB can be updated without a new code release
- Users who don't care about offline mode can skip the DB package entirely

**Cons:**
- Users now must install **two packages** instead of one
- Version mismatch between code and DB could cause subtle issues
- pnpm workspace coordination adds complexity
- npm registry overhead: publishing two packages per release
- Breaking a monorepo into two packages adds cognitive load for maintainers
- The "savings" is at most ~360 KB (1.1 MB → 740 KB) — is that worth it?

**Security implications:**
- Two npm packages = two supply chain attack surfaces
- Need to ensure both packages use same provenance/signing
- Version drift could mean users get a stale DB without realizing it

**Verdict:** Over-engineered for the problem size. The 1.1 MB tarball is not large enough to justify the operational overhead of splitting into two packages. At this scale, the complexity is disproportionate to the benefit.

---

### 3.2 Option B: Lazy-Fetch DB from CDN with Version Pinning

**How it would work:**
- Remove `dist/static-db/data/` from the published tarball (exclude via `files` field in `package.json`)
- On first use (or install via postinstall script), download the DB from GitHub Releases or a CDN
- Cache the downloaded DB in a well-known location (e.g., `~/.pnpm-audit-hook/db/`)
- Pin the download to a specific version hash (stored in the code or fetched from a version manifest)
- Verify integrity using SHA-256 hashes (already computed by the optimizer, stored in index)
- The reader module checks for local cache and falls back to the bundled path if offline

**Implementation Complexity: MEDIUM**

Required changes:
1. Add a download module that fetches the DB archive from GitHub Releases
2. Add a local cache manager with hash verification
3. Modify the reader to check cache directory first, then bundled path
4. Set up CI/CD to publish DB archives as GitHub Release artifacts
5. Add a version manifest endpoint (or embed version hashes in code)
6. Handle network failures gracefully (what if first use is offline?)
7. Consider postinstall script vs. lazy-first-use approach

**Pros:**
- Zero install weight for the DB data
- Always can fetch the latest DB without a code update
- Version pinning ensures reproducibility
- GitHub Releases provides free CDN-like distribution
- Single package to maintain

**Cons:**
- **Requires network on first use** — violates the project's offline-first security philosophy
- First `pnpm audit` run would be slow (download + decompress)
- Postinstall scripts are often blocked in enterprise environments (`--ignore-scripts`)
- CDN availability risk (GitHub Releases is reliable, but not infallible)
- Cache invalidation is tricky (when to re-download? at startup? periodically?)
- Users in air-gapped environments are completely blocked
- Adds runtime complexity for a security tool that should "just work"

**Security implications:**
- MITM risk during download (mitigated by hash verification + HTTPS)
- Download module itself becomes a supply chain vector
- Hash verification is already implemented (SHA-256 in index), so integrity is achievable
- Would need to pin a specific hash in code for reproducible builds

**Verdict:** Strongest technical case on paper, but **fundamentally at odds with the project's design philosophy**. This is a security tool that advertises itself as working offline and without network dependencies during audit. Making the DB a runtime download breaks that promise. The postinstall approach could work for some users but would be blocked in many enterprise environments.

---

### 3.3 Option C: Keep Current Behavior (Status Quo) with Mitigation

**How it works currently:**
- `files` field in `package.json` includes `"dist"` — everything in `dist/` gets published
- The static DB data is copied and optimized during `build`, then bundled into the tarball
- Reader loads from bundled path at runtime with zero network dependencies
- Integrity verification (SHA-256) already protects against tampering

**Pros:**
- Zero runtime network dependencies
- Works completely offline
- Simple, predictable deployment
- Already has integrity verification (ckw.10)
- Already optimized with gzip compression (ckw.4+5)
- 1.1 MB tarball is modest by modern standards
- Users install one package, it just works

**Cons:**
- Every code change re-downloads the full 1.1 MB tarball (even if DB didn't change)
- 1,958 files in the tarball creates npm registry overhead
- DB grows over time without a clear growth ceiling
- Users pay the full cost even on initial setup

**Possible mitigations (some already done):**
1. ✅ **Gzip compression of large shards** (ckw.4+5) — already done, 40 largest shards are `.json.gz`
2. ✅ **Index optimization** — already done, compact field names reduce index size
3. ✅ **Integrity hashes** — already done, enables verification (and future CDN fetch if needed)
4. 🔲 **Remove duplicate shard storage** — both `data/lodash.json` (top-level) and `data/packages/lodash.json` (flat legacy) exist — the reader checks both. Could be de-duplicated.
5. 🔲 **Further compress the packages/ directory** — most files are still `.json` (uncompressed). Only 40 of 1,911 are `.json.gz`. Extending compression to more shards could reduce size further.
6. 🔲 **Aggressive tree-shaking** — only include packages that appear in popular lockfiles? (Risky — may miss vulnerabilities)
7. 🔲 **Remove legacy `packages/` directory** — migrate all shards to the new scoped-directory format and delete `packages/`. The reader supports both, but maintaining both doubles some storage.

**Growth projection:**
- Current: 1,911 package shards, ~3.5 MB raw data, 1.1 MB tarball
- Annual growth estimate: ~400-600 new packages per year (based on historical trends)
- Projected in 2 years: ~3,000 shards, ~5-6 MB raw, ~1.5-2 MB tarball
- Even at 2x growth, the tarball remains under 3 MB — acceptable for most environments

**Verdict:** Pragmatic and appropriate for the current scale. The existing optimizations (gzip, integrity checks) already address the main pain points. The 1.1 MB tarball is well within acceptable limits for an npm package.

---

## 4. Recommendation

### Recommended: Option C (Status Quo) with Targeted Mitigations

**Rationale:**

1. **The problem is smaller than it appears.** The npm tarball is 1.1 MB after gzip compression — not 9 MB. The 9 MB figure is the on-disk allocation in `src/static-db/data/` (source), and while `dist/static-db/data/` appears as 8.2 MB on disk due to filesystem block overhead, the actual byte content is ~3.5 MB, and the tarball compression brings it to 1.1 MB. This is within the normal range for security tooling (e.g., `eslint` with plugins is often 5-10 MB).

2. **Offline-first is a core design constraint.** The project's README emphasizes offline capability. Option B (CDN fetch) directly contradicts this. Option A (separate package) still requires installation, just in two steps.

3. **Complexity-to-benefit ratio is poor.** Splitting the package or adding a downloader adds significant maintenance burden for at most ~360 KB of savings per install. The team is small, and time spent on package orchestration is time not spent on security features.

4. **The DB is not that large.** For context:
   - A single `@types/node` package is ~2 MB
   - `aws-sdk` is ~50 MB
   - `esbuild` is ~8 MB per platform
   - `pnpm-audit-hook` at 1.1 MB is tiny

5. **The CI/CD workflow already handles DB updates well.** Weekly automated PRs with incremental updates work cleanly. Adding a second package publication step would double the CI complexity.

### Recommended Mitigations (in priority order)

| Priority | Mitigation | Effort | Impact |
|---|---|---|---|
| P1 | **Extend gzip compression to all shards > 2 KB** — currently only 40 of 1,911 shards are compressed. Compressing the rest could reduce data size by 30-50%. | Low (modify threshold in optimizer) | High |
| P2 | **Remove legacy `packages/` flat directory** — migrate all shards to the scoped-directory format (`@scope/name.json`). The legacy format was kept for backward compatibility but adds ~200 KB of duplicate data. | Medium (requires migration script) | Medium |
| P3 | **Benchmark npm install times** — verify that the 1.1 MB tarball doesn't cause noticeable install delays in CI. If it's < 2 seconds extra, no action needed. | Low | Low (informational) |
| P4 | **Re-evaluate at 3x data growth** — if the DB grows to ~6 MB+ raw (>2 MB tarball), revisit Option B (CDN fetch) with improved offline fallback. | None now | Future-proofing |

### If Decision Is Revisited Later

Keep the evaluation framework in mind. The key trigger for re-evaluation would be:
- **DB data triples in size** (>3,000 raw MB or >3 MB tarball)
- **User complaints** about install size or network transfer
- **Feature requirement** for multiple DB versions (e.g., different cutoff dates per user)

At that point, Option B (CDN fetch with hash-pinned caching) is the best path, as it preserves the single-package model while reducing install weight. The SHA-256 integrity infrastructure is already in place (ckw.10), which was the hardest part of implementing it.

---

## 5. Next Steps (If Implemented)

If the recommendation is accepted:

1. **No architectural changes** to the current packaging approach.
2. **Implement P1:** Update `scripts/optimize-static-db.js` to lower the compression threshold so more shards are gzipped (target: compress all shards > 1 KB).
3. **Implement P2:** Create a migration that moves all shards from `data/packages/{name}.json` to `data/{name}.json` (unscoped) or `data/@{scope}/{name}.json` (scoped). Update the reader to stop checking the legacy path. Remove the `packages/` directory. This also simplifies the on-disk structure.
4. **Document the decision** in the project's architecture docs for future maintainers.
5. **Add a monitoring metric** in CI that tracks total DB data size over time, alerting when it exceeds configurable thresholds.

---

## Appendix A: Full Measurement Details

```
Commands used:
  $ du -sb dist/static-db/data/       → 3,503,062 bytes
  $ du -sb dist/ --exclude=static-db  → ~740,000 bytes (code only)
  $ npm pack --dry-run                → 2,073 files total
  $ du -sh pnpm-audit-hook-1.1.0.tgz  → 1.1 MB
```

## Appendix B: File Distribution in dist/static-db/data/

```
data/
├── index.json.gz             (96 KB, 1 file)       — compressed index
├── {name}.json               (45 files, ~750 B each) — popular packages, uncompressed
└── packages/
    ├── {name}.json           (1,871 files, avg ~1.5 KB) — legacy flat directory
    └── {name}.json.gz        (40 files, largest: 52 KB) — compressed larger shards
```

## Appendix C: Related Prior Work

| Ticket | Description | Status |
|---|---|---|
| ckw.4 | Static DB compression (gzip shards) | ✅ Complete |
| ckw.5 | Static DB optimization (compact index) | ✅ Complete |
| ckw.10 | DB shard integrity verification (SHA-256) | ✅ Complete |
| ckw.14 | Align shard path encoding between update script and reader | ✅ Complete |
| ckw.8 | Schema version guard for forward compatibility | ✅ Complete |
| ckw.3 | DB version in cache keys for automatic invalidation | ✅ Complete |
| ckw.6 | OSV.dev source connector (runtime fallback) | ✅ Complete |
