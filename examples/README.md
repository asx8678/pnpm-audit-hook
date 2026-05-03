# pnpm-audit-hook Examples

> Runnable examples demonstrating the pnpm-audit-hook API and SBOM features.

## Prerequisites

- **Node.js** >= 18
- **pnpm** installed (`corepack enable`)
- Project dependencies installed (`pnpm install`)
- **tsx** for running TypeScript directly (`npx tsx`)

## Quick Start

```bash
# Install dependencies from the project root
pnpm install

# Run any example (imports resolve from src/ — no build step needed)
npx tsx examples/basic-usage.ts
```

## Examples

| Example | Description | Run Command |
|---------|-------------|-------------|
| [basic-usage.ts](./basic-usage.ts) | Core audit API — run audits, read config, process results, check for vulnerabilities | `npx tsx examples/basic-usage.ts` |
| [sbom-generation.ts](./sbom-generation.ts) | SBOM generation — CycloneDX, SPDX, SWID Tags, write to file, use the generator factory | `npx tsx examples/sbom-generation.ts` |
| [sbom-diff.ts](./sbom-diff.ts) | SBOM diffing — load two SBOMs, compare them, display the diff, format output | `npx tsx examples/sbom-diff.ts` |
| [dependency-tree.ts](./dependency-tree.ts) | Dependency tree — build from SBOM, render ASCII/JSON, limit depth, show vulnerability markers | `npx tsx examples/dependency-tree.ts` |
| [ci-integration.ts](./ci-integration.ts) | CI/CD — configure for GitHub Actions, Azure DevOps, AWS CodeBuild, handle exit codes | `npx tsx examples/ci-integration.ts` |

## Running All Examples

```bash
# Run each example in sequence
for f in examples/*.ts; do
  echo "=== Running $f ==="
  npx tsx "$f"
  echo ""
done
```

## Example Details

### 1. Basic Audit (`basic-usage.ts`)

Demonstrates the core `runAudit()` API:
- Setting up runtime options and lockfile parsing
- Running a complete vulnerability audit
- Reading configuration from `.pnpm-audit.yaml`
- Processing and grouping findings by severity
- Checking for fixable vulnerabilities
- Handling exit codes properly

### 2. SBOM Generation (`sbom-generation.ts`)

Demonstrates generating Software Bill of Materials:
- Generating CycloneDX 1.5 JSON SBOMs
- Generating CycloneDX XML SBOMs
- Generating SPDX 2.3 SBOMs
- Generating SWID Tags (ISO/IEC 19770-2)
- Writing SBOMs to files
- Validating generated SBOMs against schemas
- Using the generator factory with different options

### 3. SBOM Diff (`sbom-diff.ts`)

Demonstrates comparing two SBOM documents:
- Loading CycloneDX and SPDX SBOM files
- Detecting format automatically
- Comparing added, removed, and updated packages
- Displaying diff summaries
- Cross-format comparison (CycloneDX vs SPDX)
- Formatting diff output for different use cases

### 4. Dependency Tree (`dependency-tree.ts`)

Demonstrates dependency tree visualization:
- Building a tree from a CycloneDX SBOM
- Building a tree from a pnpm lockfile
- Rendering as ASCII art with box-drawing characters
- Rendering as JSON output
- Limiting tree traversal depth
- Highlighting vulnerable packages with markers

### 5. CI/CD Integration (`ci-integration.ts`)

Demonstrates CI/CD pipeline integration:
- Configuring for GitHub Actions workflows
- Configuring for Azure DevOps pipelines
- Configuring for AWS CodeBuild
- Configuring for GitLab CI
- Setting output formats (JSON, SARIF-compatible)
- Handling exit codes (`EXIT_CODES.BLOCKED`, etc.)
- Setting up environment variable overrides

## Related Documentation

- [API Reference](../docs/api/README.md)
- [Audit API](../docs/api/audit.md)
- [SBOM API](../docs/api/sbom.md)
- [Configuration API](../docs/api/config.md)
- [CI/CD Integration](../docs/ci-cd/README.md)
- [Main README](../README.md)
