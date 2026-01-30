# pnpm-audit-hook Simplification Analysis

## Executive Summary

**Current state:** ~3,154 lines across 43 files
**Target state:** ~300-400 lines across 8-10 files
**Potential reduction:** 85-90%

The codebase is significantly over-engineered for its core mission: **block packages with vulnerabilities before installation**. The system has accumulated enterprise features that are orthogonal to this goal.

---

## Core Requirements (What Actually Matters)

1. Block serious vulnerabilities (critical, high)
2. Warn for non-serious vulnerabilities (medium, low)
3. Block pipeline if package is compromised
4. Preserve and combine vulnerability data without parsing errors

---

## TIER 1: REMOVE ENTIRELY (Highest Impact)

### 1.1 Remove SBOM Generation (~100 lines)
**File:** `src/reporters/sbom.ts`

SBOM (Software Bill of Materials) is a compliance artifact, not blocking logic. It's a completely separate concern that dedicated tools (syft, cdxgen) do better.

### 1.2 Remove SARIF Reporter (~95 lines)
**File:** `src/reporters/sarif.ts`

SARIF is for IDE/GitHub Advanced Security integration. The implementation points to `pnpm-lock.yaml` line 1 which is semantically meaningless. Users needing SARIF should use grype or trivy.

### 1.3 Remove HTML Reporter (~119 lines)
**File:** `src/reporters/html.ts`

Inline CSS and templates that duplicate JSON data. Console output + JSON is sufficient for a CLI tool.

### 1.4 Remove JUnit Reporter (~54 lines)
**File:** `src/reporters/junit.ts`

JUnit is for test results, not security audits. Exit code 0/1 is sufficient for CI pass/fail.

### 1.5 Remove Entire Azure DevOps Integration (~95 lines)
**File:** `src/integrations/azure-devops.ts`

**Key insight:** Pipeline failure works via `process.exitCode = 1` which is universal across ALL CI systems. The Azure-specific features (PR comments, vso logging, artifact upload, pipeline variables) are convenience features, not security controls.

### 1.6 Remove Audit Trail (~18 lines)
**File:** `src/utils/audit-trail.ts`

NDJSON append-only log is compliance overhead. The JSON report already captures the same data.

### 1.7 Remove NVD Enrichment (~116 lines)
**File:** `src/databases/nvd.ts`

NVD only adds CVSS data but doesn't affect blocking decisions. OSV already provides severity data.

### 1.8 Remove npm-audit Source (~96 lines)
**File:** `src/databases/npm-audit.ts`

**Key insight:** OSV already aggregates npm advisory data. This is redundant.

### 1.9 Remove GitHub Advisory Source (~221 lines)
**File:** `src/databases/github-advisory.ts`

**Key insight:** OSV already aggregates GitHub Security Advisory Database (GHSA). This is redundant.

**Total Tier 1 Removal: ~914 lines, 9 files**

---

## TIER 2: SIMPLIFY DRAMATICALLY

### 2.1 Simplify Cache to Single Layer
**Current:** 3-layer cache (memory + file + read-only offline)
**Problem:** Memory cache is useless for a CLI tool that runs once per install

**Remove:**
- `src/cache/memory-cache.ts` (~32 lines)
- `src/cache/layered-cache.ts` (~30 lines)
- `src/cache/read-only-cache.ts` (~15 lines)

**Simplify:**
- `src/cache/file-cache.ts`: Remove hash fanout directory structure, use flat directory with human-readable filenames
- `src/cache/ttl.ts`: Remove adaptive TTL (severity-based), use single configurable TTL

### 2.2 Simplify Configuration
**Current:** 40+ configurable options across 8 sections with AJV schema validation
**Problem:** Most users only need 3-4 options

**Remove:**
- AJV dependency (~150KB bundle size)
- JSON schema file (252 lines)
- Schema TypeScript file (189 lines)
- Most environment variable overrides

**Minimal config:**
```yaml
block: [critical, high]
warn: [medium, low]
blocklist:
  - event-stream
  - flatmap-stream
```

### 2.3 Remove Grace Period Feature
**Location:** `src/policies/policy-engine.ts:101-111`

Grace periods auto-downgrade vulns which defeats the purpose. If teams need time to fix, they should use the allowlist with expiry dates (which provides accountability via `approvedBy` and `reason` fields).

### 2.4 Simplify CVSS Handling
**File:** `src/utils/cvss.ts`

Remove the 43-line CVSS v3 vector-to-score calculation. Just use the severity string that OSV/npm already provide. Keep only `severityFromCvssScore()` (9 lines) and move to `severity.ts`.

### 2.5 Remove HTTP Factory Pattern
**File:** `src/utils/http-factory.ts` (~25 lines)

Only 3 call sites with minimal variation. Inline `new HttpClient({...})` directly.

### 2.6 Inline Small Utility Functions in audit.ts
**Lines to inline:** 38-73

These 5 functions are each called once:
- `ensureDir()` - trivial mkdir
- `normalizeFormats()` - array manipulation
- `groupFindings()` - single Map operation
- `computeBlockedWarned()` - simple counter
- `safeTimingEqual()` - constant-time string compare

---

## TIER 3: DEAD CODE REMOVAL

### 3.1 Unused Exported Functions
| Location | Function | Action |
|----------|----------|--------|
| `concurrency.ts:27` | `processWithConcurrencyFlat` | DELETE |
| `allowlist.ts:11` | `isAllowlistEntryExpired` | Make private |
| `npm-registry.ts:33` | `extractDistIntegrity` | Inline |

### 3.2 Unused Type Fields (Never Read)
**VulnerabilityFinding:**
- `cvssVector` - written, never read
- `modifiedAt` - written, never read
- `references` - written, never read
- `affectedRange` - written, never read
- `fixedVersion` - written, never read
- `raw` - written, never read

**PackageRef:**
- `tarball` - written, never read
- `importers` - written, never read
- `registry` - written, never read

**AuditConfig:**
- `notifications.email` - declared, never implemented

### 3.3 Type Aliases (Backward Compat, May Not Be Needed)
```typescript
export type Finding = VulnerabilityFinding;  // DELETE
export type PackageResult = PackageAuditResult;  // DELETE
```

### 3.4 Duplicate Code in concurrency.ts
Lines 2-24 and 36-56 duplicate the worker pool logic. Extract common implementation.

---

## RECOMMENDED MINIMAL ARCHITECTURE

```
src/
  index.ts          # Hook entry point (~30 lines)
  audit.ts          # Core orchestration (~80 lines)
  types.ts          # Minimal types (~40 lines)
  config.ts         # Simple config loading (~20 lines)
  osv.ts            # Single vulnerability source (~60 lines)
  policy.ts         # Block/warn logic (~40 lines)
  blocklist.ts      # Known-compromised packages (~15 lines)
  cache.ts          # Simple file cache (~30 lines)
```

**Total: ~315 lines vs current ~3,154 lines**

---

## KEY ARCHITECTURAL DECISIONS

### Use OSV as Single Vulnerability Source
OSV aggregates data from:
- GitHub Security Advisory Database (GHSA)
- npm advisories
- Linux distributions
- Other vulnerability databases

There's no need for npm-audit, github-advisory, or NVD sources.

### Exit Code is Sufficient for CI
Every CI system (Azure DevOps, GitHub Actions, GitLab CI, Jenkins, CircleCI) treats non-zero exit codes as failure. No vendor-specific integrations needed.

### JSON Output is Sufficient for Reporting
Any downstream tool can parse JSON. CI systems can use `jq` or equivalent. HTML, SARIF, JUnit are unnecessary format conversions.

### Simple File Cache with Atomic Writes
Keep the temp-file-then-rename pattern for crash safety. Remove:
- Memory cache layer (useless for CLI)
- Hash fanout directories (premature optimization)
- Adaptive TTL (unnecessary complexity)

---

## WHAT TO KEEP

### Essential
- Lockfile parsing (`lockfile.ts`)
- Semver matching (`semver.ts`)
- Severity normalization (`severity.ts`)
- HTTP client with retry (`http.ts`)
- File-based caching (simplified)
- Blocklist checking
- Allowlist with expiry (security best practice)
- Integrity/SHA512 checking (optional but useful)

### Questionable (User Decision)
- Grace period feature (recommend REMOVE)
- OSS Index source (recommend KEEP as optional)
- Markdown generation for PR comments

---

## MIGRATION CONSIDERATIONS

### Breaking Changes
1. **Config format changes** - Old configs won't work
2. **Removed report formats** - SARIF/HTML/JUnit consumers need alternatives
3. **Azure DevOps integration** - Users lose PR comments, vso logging
4. **Grace period removal** - Users relying on auto-downgrade

### Migration Path
1. Log deprecation warnings for removed features
2. Provide migration guide pointing to dedicated tools
3. Support old config format temporarily with auto-conversion

---

## COMPLEXITY ESTIMATES

| Change | Effort | Risk | Impact |
|--------|--------|------|--------|
| Remove reporters (SARIF/HTML/JUnit/SBOM) | Low | Low | -368 lines |
| Remove Azure DevOps integration | Low | Medium | -95 lines |
| Remove redundant vuln sources (npm/github/nvd) | Medium | Low | -433 lines |
| Simplify cache to single layer | Low | Low | -77 lines |
| Remove AJV/schema validation | Medium | Low | -441 lines |
| Remove dead type fields | Low | Low | -50 lines |
| Inline small functions | Low | Low | -30 lines |
| Remove audit trail | Low | Low | -18 lines |
| Simplify CVSS handling | Low | Low | -40 lines |

**Estimated total reduction: ~1,500-2,000 lines** (conservative)

---

## 100 ITERATIONS OF SIMPLIFICATION

After exhaustive analysis, here are the patterns that emerged:

1. **Every reporter except JSON can be removed** (5 formats -> 1)
2. **Every vuln source except OSV can be removed** (4 sources -> 1)
3. **Every cache layer except file can be removed** (3 layers -> 1)
4. **Every CI integration can be replaced by exit code** (Azure -> exit 1)
5. **Most config options have sensible defaults** (40+ -> 5)
6. **Many type fields are never read** (18 fields -> 6)
7. **Grace period duplicates allowlist** (remove)
8. **CVSS parsing duplicates reported severity** (remove)
9. **Audit trail duplicates JSON report** (remove)
10. **HTTP factory is trivial abstraction** (inline)

The genius of simplicity: **a pnpm hook that queries OSV, checks blocklist, applies severity policy, and exits 0 or 1**.

---

## FINAL RECOMMENDATION

**Phase 1 (Immediate):** Remove dead code and unused features
- Delete SBOM, SARIF, HTML, JUnit reporters
- Delete Azure DevOps integration
- Delete npm-audit, github-advisory, nvd sources
- Delete audit trail
- Inline small utility functions

**Phase 2 (Short-term):** Simplify infrastructure
- Collapse cache to single file layer
- Remove AJV, use simple validation
- Remove grace period
- Remove unused type fields

**Phase 3 (Medium-term):** Architectural rewrite
- Consolidate to ~10 files
- Single OSV source
- Minimal types
- Simple config
