# Phase 6, Task 6.3: Improved Dependency Chain Analysis

## Status: ✅ Complete

## Summary

Enhanced dependency chain analysis with CVSS integration, severity propagation, risk scoring, and richer vulnerability context. The system now provides security teams with actionable intelligence about how vulnerabilities propagate through dependency chains, enabling better prioritization and remediation decisions.

## Changes Made

### 1. Enhanced CVSS Module (`src/utils/cvss.ts`)

**Before:** Single function `cvssV3VectorToSeverity()` that converted CVSS vectors to severity strings.

**After:** Full CVSS v3.x processing suite:
- **`cvssV3ToScore(vector)`** — Returns the numeric CVSS score (0.0–10.0) with proper NVD-spec rounding
- **`scoreToSeverity(score)`** — Converts numeric scores to severity labels
- **`parseCvssV3(vector)`** — Complete parse returning score, severity, all metric values, human-readable labels, and exploitability summary
- **`cvssV3VectorToSeverity()`** — Preserved for backward compatibility, now implemented on top of the new functions

Key improvements:
- Extracted `parseCvssV3Vector()` as internal helper for reuse
- Fixed a bug where `CIA_WEIGHTS["N"] = 0.0` was treated as falsy (`!0.0 === true`), causing "None" confidentiality/integrity/availability to incorrectly return "unknown"
- Added NVD-spec `1e-10` epsilon for floating-point rounding

### 2. New Dependency Chain Analyzer (`src/utils/lockfile/dependency-chain-analyzer.ts`)

A new module with 4 core capabilities:

#### Severity Propagation (`propagateSeverity`)
Adjusts vulnerability severity based on chain context:
- **Direct dependencies:** No adjustment (full severity)
- **Transitive depth ≤ 2:** No downgrade (close to control surface)
- **Transitive depth 3–5:** Downgrade by 1 level
- **Transitive depth > 5:** Downgrade by 1 level (capped)
- **Dev-only transitive:** Additional 1-level downgrade
- Never downgrades below "low"

#### Risk Factor Computation
Weighted composite risk scoring with 5 factors:
| Factor | Weight | Description |
|--------|--------|-------------|
| CVSS Base | 0.50 | Numeric CVSS score |
| Chain Depth | 0.10 | Depth from nearest direct dependency |
| Blast Radius | 0.10 | Log-scaled count of affected packages |
| Fix Availability | 0.15 | 2.0 if fix exists, 8.0 if not |
| Exploitability | 0.15 | Derived from CVSS AV/AC/PR/UI metrics |

Dev-only dependencies get a 30% reduction to the composite score.

#### Exploitability Estimation
Derives an exploitability score (0–1) from CVSS metrics:
- Attack Vector (0–0.4): Network > Adjacent > Local > Physical
- Attack Complexity (0–0.3): Low > High
- Privileges Required (0–0.2): None > Low > High
- User Interaction (0–0.1): None > Required

#### Main Analysis (`analyzeVulnerability`)
Enriches each `VulnerabilityFinding` with:
- Chain context (depth, paths, affected count, propagated severity, direct ancestors)
- CVSS details (parsed metrics, exploitability label)
- Risk factors and composite score

### 3. Enhanced Types (`src/types.ts`)

New interfaces:
- **`VulnerabilityChainContext`** — Chain analysis results attached to findings
- **`CvssFindingDetails`** — Parsed CVSS metrics for rich context display

### 4. Output Enhancement (`src/utils/output-formatter.ts`)

Human-readable output now shows:
- Dependency type (direct/transitive)
- Chain depth from nearest direct dependency
- Blast radius (affected package count)
- Propagated severity (when adjusted)
- Direct ancestors that introduce the vulnerability
- Composite risk score (0–10)
- CVSS exploitability label (e.g., "remotely exploitable, no user interaction, no privileges required")

### 5. Audit Integration (`src/audit.ts`)

- Findings are now enriched with full chain analysis after dependency graph construction
- Findings are sorted by composite risk score (highest risk first)
- Both enriched and sorted findings flow into policy evaluation and output

### 6. Barrel Export Fix (`src/utils/lockfile/graph-builder.ts`)

- Added missing import of `parsePnpmPackageKey` and `makeGraphKey` from `package-key-parser.js`
- This was a pre-existing issue that prevented TypeScript compilation without the import

## Testing

### New Tests
- **`test/utils/cvss.test.ts`** — 24 tests (expanded from 13):
  - `cvssV3ToScore`: numeric scores, null for invalid, zero-impact handling
  - `scoreToSeverity`: boundary tests for all severity levels
  - `parseCvssV3`: full parse results, vector labels, exploitability text
  - All existing backward-compat tests preserved

- **`test/utils/dependency-chain-analyzer.test.ts`** — 20 new tests:
  - `propagateSeverity`: 8 tests covering direct, shallow, deep, dev-only, boundary cases
  - `analyzeVulnerability`: 8 tests for direct/transitive enrichment, CVSS details, risk factors, fix/dev adjustments
  - `analyzeAllVulnerabilities`: batch processing
  - `sortByRisk`: sorting, immutability, fallback behavior

### Test Results
```
753 tests | 254 suites | 753 pass | 0 fail
TypeScript: 0 errors
Duration: ~15s
```

## Files Modified
| File | Change |
|------|--------|
| `src/utils/cvss.ts` | Enhanced with `cvssV3ToScore`, `scoreToSeverity`, `parseCvssV3` |
| `src/utils/lockfile/dependency-chain-analyzer.ts` | **New file** — chain analyzer with CVSS integration |
| `src/utils/lockfile/index.ts` | Added re-exports for new analyzer functions |
| `src/utils/lockfile/graph-builder.ts` | Added missing `parsePnpmPackageKey`/`makeGraphKey` import |
| `src/types.ts` | Added `VulnerabilityChainContext`, `CvssFindingDetails` interfaces |
| `src/utils/output-formatter.ts` | Enhanced vulnerability details display |
| `src/audit.ts` | Integrated `analyzeAllVulnerabilities` + `sortByRisk` |
| `test/utils/cvss.test.ts` | Expanded test coverage for new CVSS functions |
| `test/utils/dependency-chain-analyzer.test.ts` | **New file** — 20 tests for chain analyzer |
