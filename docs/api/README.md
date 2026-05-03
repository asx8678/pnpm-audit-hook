# pnpm-audit-hook API Reference

> Programmatic API for pnpm-audit-hook — a pre-download security gate that blocks vulnerable packages before they reach your `node_modules`.

## Installation

```bash
npm install pnpm-audit-hook
# or
pnpm add pnpm-audit-hook
```

## Quick Start

```typescript
import { runAudit, createPnpmHooks } from 'pnpm-audit-hook';

// Option 1: Use the pnpm hooks API (recommended for pnpm integration)
const hooks = createPnpmHooks();

// Option 2: Use the audit API directly
const lockfile = { /* your lockfile object */ };
const runtime = {
  cwd: process.cwd(),
  registryUrl: 'https://registry.npmjs.org',
  env: process.env,
};

const result = await runAudit(lockfile, runtime);
if (result.blocked) {
  console.error('Installation blocked due to vulnerabilities!');
  process.exit(result.exitCode);
}
```

## API Modules

| Module | Description |
|--------|-------------|
| [Audit API](./audit.md) | Core audit functionality — run audits, interpret results |
| [Configuration API](./config.md) | Load and manage audit configuration |
| [Type Definitions](./types.md) | All TypeScript interfaces and types |
| [Color Utilities](./color-utils.md) | Terminal color and formatting utilities |
| [Usage Examples](./examples.md) | Real-world integration examples |
| [Migration Guide](./migration.md) | Upgrading between versions |

## Core Concepts

### Architecture Overview

```
pnpm install/add/update
        │
        ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Resolve lockfile │ ──▶ │ Audit packages   │ ──▶ │ Apply policies  │
└─────────────────┘     └────────┬─────────┘     └────────┬────────┘
                                 │                         │
                    ┌────────────┴────────────┐            │
                    ▼                         ▼            ▼
           ┌──────────────┐          ┌──────────────┐  ┌─────────┐
           │ Live sources │          │ Static DB    │  │ allow/  │
           │ GHSA / OSV   │          │ (offline)    │  │ warn /  │
           └──────────────┘          └──────────────┘  │ block   │
                                                       └─────────┘
```

### Key Abstractions

1. **PnpmLockfile** — The resolved lockfile structure passed to hooks
2. **VulnerabilityFinding** — A single vulnerability detected in a package
3. **PolicyDecision** — The action taken for each finding (allow/warn/block)
4. **AuditResult** — Complete audit result including findings, decisions, and metadata

### Exit Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `EXIT_CODES.SUCCESS` | No vulnerabilities or all allowed |
| 1 | `EXIT_CODES.BLOCKED` | Installation blocked by policy |
| 2 | `EXIT_CODES.WARNINGS` | Warnings present but not blocked |
| 3 | `EXIT_CODES.SOURCE_ERROR` | Vulnerability source failed |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PNPM_AUDIT_CONFIG_PATH` | Custom config file path | `.pnpm-audit.yaml` |
| `PNPM_AUDIT_BLOCK_SEVERITY` | Override block severities (comma-separated) | `critical,high` |
| `PNPM_AUDIT_FAIL_ON_NO_SOURCES` | Fail when all sources disabled | `true` |
| `PNPM_AUDIT_FAIL_ON_SOURCE_ERROR` | Fail when source errors occur | `true` |
| `PNPM_AUDIT_OFFLINE` | Use only static DB + cache | `false` |
| `NO_COLOR` | Disable color output | — |
| `FORCE_COLOR` | Force color output | — |

## TypeScript Support

This package includes full TypeScript declarations. Import types directly:

```typescript
import type {
  AuditResult,
  AuditConfig,
  AuditConfigInput,
  VulnerabilityFinding,
  PolicyDecision,
  Severity,
  PnpmLockfile,
} from 'pnpm-audit-hook';
```

## Further Reading

- [Configuration Guide](../README.md#configuration)
- [Troubleshooting](../troubleshooting.md)
- [CI/CD Integration](../README.md#cicd-integration)
- [Architecture Overview](../README.md#architecture)
