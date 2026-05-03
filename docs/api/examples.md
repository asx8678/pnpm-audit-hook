# Usage Examples

> Real-world examples for integrating pnpm-audit-hook into your projects.

## Table of Contents

- [Basic Integration](#basic-integration)
- [Custom Policy](#custom-policy)
- [CI/CD Integration](#cicd-integration)
- [Programmatic Usage](#programmatic-usage)
- [Color Utilities](#color-utilities)
- [Error Handling](#error-handling)

---

## Basic Integration

### Minimal .pnpmfile.cjs

The simplest way to enable auditing:

```javascript
// .pnpmfile.cjs
const { createPnpmHooks } = require('pnpm-audit-hook');
module.exports = createPnpmHooks();
```

### Minimal Configuration

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
    - high
```

---

## Custom Policy

### Block Only Critical

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
  warn:
    - high
    - medium
    - low
    - unknown
```

### Allowlist Exceptions

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
    - high
  allowlist:
    # Allow a specific CVE that doesn't affect us
    - id: CVE-2021-44228
      reason: "Log4Shell - we don't use JNDI lookup"

    # Allow a package with version constraint
    - package: lodash
      version: ">=4.17.21"
      reason: "Risk accepted, patched version"

    # Allow only for direct dependencies
    - package: moment
      directOnly: true
      reason: "Dev dependency only"

    # Time-limited exception
    - package: axios
      expires: "2025-06-01"
      reason: "Migration in progress"
```

### Transitive Dependency Handling

```yaml
# .pnpm-audit.yaml
policy:
  block:
    - critical
  warn:
    - high
    - medium

  # Downgrade severity for transitive dependencies
  # critical → high, high → medium, medium → low
  transitiveSeverityOverride: downgrade-by-one
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: Run audit
        run: pnpm audit --audit-level=high
        continue-on-error: false
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security-audit:
  stage: test
  image: node:20
  before_script:
    - corepack enable
    - corepack prepare pnpm@latest --activate
    - pnpm install --frozen-lockfile
  script:
    - pnpm audit --audit-level=high
  rules:
    - if: '$CI_MERGE_REQUEST_IID'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20'
    displayName: 'Install Node.js'

  - script: |
      corepack enable
      pnpm install --frozen-lockfile
    displayName: 'Install dependencies'

  - script: pnpm audit --audit-level=high
    displayName: 'Security audit'
```

---

## Programmatic Usage

### Basic Audit

```typescript
import { runAudit } from 'pnpm-audit-hook';
import fs from 'node:fs/promises';
import YAML from 'yaml';

async function performAudit() {
  // Load lockfile
  const lockfileContent = await fs.readFile('pnpm-lock.yaml', 'utf-8');
  const lockfile = YAML.parse(lockfileContent);

  // Run audit
  const result = await runAudit(lockfile, {
    cwd: process.cwd(),
    registryUrl: 'https://registry.npmjs.org',
    env: process.env,
  });

  // Handle results
  if (result.blocked) {
    console.error('❌ Installation blocked!');
    console.error(`Found ${result.findings.length} vulnerabilities`);

    // Group by severity
    const critical = result.findings.filter(f => f.severity === 'critical');
    const high = result.findings.filter(f => f.severity === 'high');

    if (critical.length > 0) {
      console.error('\n🔴 Critical:');
      for (const f of critical) {
        console.error(`  - ${f.packageName}@${f.packageVersion}: ${f.id}`);
      }
    }

    if (high.length > 0) {
      console.error('\n🟠 High:');
      for (const f of high) {
        console.error(`  - ${f.packageName}@${f.packageVersion}: ${f.id}`);
      }
    }

    process.exit(1);
  }

  console.log('✅ Audit passed');
  return result;
}
```

### Analyzing Vulnerability Chains

```typescript
import { runAudit } from 'pnpm-audit-hook';

async function analyzeChains() {
  const result = await runAudit(lockfile, runtime);

  // Find transitive vulnerabilities with long chains
  const transitive = result.findings.filter(f => {
    const depth = f.chainContext?.chainDepth ?? 0;
    return depth > 2;
  });

  console.log(`\n📦 Transitive vulnerabilities with deep chains:`);
  for (const f of transitive) {
    const chain = f.dependencyChain ?? [];
    console.log(`\n  ${f.packageName}@${f.packageVersion}`);
    console.log(`  Chain depth: ${f.chainContext?.chainDepth}`);
    console.log(`  Path: ${chain.join(' → ')}`);
  }
}
```

### Custom Reporting

```typescript
import { runAudit, type VulnerabilityFinding, type PolicyDecision } from 'pnpm-audit-hook';

function generateReport(result: Awaited<ReturnType<typeof runAudit>>) {
  const lines: string[] = [];

  lines.push('=== Security Audit Report ===\n');
  lines.push(`Packages audited: ${result.totalPackages}`);
  lines.push(`Vulnerabilities found: ${result.findings.length}`);
  lines.push(`Duration: ${result.durationMs}ms\n`);

  // Source status
  lines.push('--- Source Status ---');
  for (const [name, status] of Object.entries(result.sourceStatus)) {
    const icon = status.ok ? '✅' : '❌';
    lines.push(`${icon} ${name}: ${status.ok ? 'OK' : status.error}`);
  }

  // Findings by package
  lines.push('\n--- Findings by Package ---');
  const byPackage = groupBy(result.findings, f => `${f.packageName}@${f.packageVersion}`);

  for (const [pkg, findings] of Object.entries(byPackage)) {
    lines.push(`\n${pkg}:`);
    for (const f of findings) {
      const fix = f.fixedVersion ? ` (fix: ${f.fixedVersion})` : '';
      lines.push(`  [${f.severity.toUpperCase()}] ${f.id}${fix}`);
    }
  }

  // Decisions
  lines.push('\n--- Policy Decisions ---');
  const blocked = result.decisions.filter(d => d.action === 'block');
  const warned = result.decisions.filter(d => d.action === 'warn');

  lines.push(`Blocked: ${blocked.length}`);
  lines.push(`Warnings: ${warned.length}`);

  return lines.join('\n');
}

function groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, T[]> {
  return items.reduce((acc, item) => {
    const key = keyFn(item);
    (acc[key] ??= []).push(item);
    return acc;
  }, {} as Record<string, T[]>);
}
```

---

## Color Utilities

### Basic Color Usage

```typescript
import {
  severityColor,
  severityLabel,
  formatError,
  formatWarning,
  formatSuccess,
} from 'pnpm-audit-hook';

// Color a severity
const redText = severityColor('critical');  // \x1b[31m
const label = severityLabel('critical');    // CRITICAL

// Format messages
const error = formatError('Blocked', ['CVE-2021-44228 found']);
const warning = formatWarning('Warning', ['Medium severity issue']);
const success = formatSuccess('Passed', ['No blocking issues']);
```

### Building Custom Output

```typescript
import {
  box,
  sectionHeader,
  horizontalLine,
  indent,
  listItem,
  truncate,
  pad,
  center,
  BOLD,
  RESET,
  RED,
  GREEN,
  YELLOW,
} from 'pnpm-audit-hook';

function renderDashboard(findings: VulnerabilityFinding[]) {
  const lines: string[] = [];

  // Header
  lines.push(box('Security Dashboard', 'double'));
  lines.push('');

  // Summary section
  lines.push(sectionHeader('Summary'));
  lines.push(indent(`Total findings: ${findings.length}`, 2));
  lines.push('');

  // By severity
  const bySeverity = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    medium: findings.filter(f => f.severity === 'medium'),
    low: findings.filter(f => f.severity === 'low'),
  };

  lines.push(sectionHeader('By Severity'));
  lines.push(listItem(`${RED}${BOLD}Critical: ${bySeverity.critical.length}${RESET}`, 0));
  lines.push(listItem(`${RED}High: ${bySeverity.high.length}${RESET}`, 0));
  lines.push(listItem(`${YELLOW}Medium: ${bySeverity.medium.length}${RESET}`, 0));
  lines.push(listItem(`Low: ${bySeverity.low.length}`, 0));

  return lines.join('\n');
}
```

### Progress Reporting

```typescript
import { progressBar, spinnerChar } from 'pnpm-audit-hook';

function showProgress(current: number, total: number, frame: number) {
  const progress = current / total;
  const bar = progressBar(progress, 30, '█', '░');
  const spinner = spinnerChar(frame);

  process.stdout.write(`\r${spinner} ${bar} ${current}/${total}`);
}
```

---

## Error Handling

### Handling Config Errors

```typescript
import { loadConfig } from 'pnpm-audit-hook/config';

async function safeConfigLoad() {
  try {
    const config = await loadConfig({
      cwd: process.cwd(),
      env: process.env,
    });
    return config;
  } catch (error) {
    if (error instanceof Error) {
      // YAML parse error
      if (error.message.includes('Failed to read config')) {
        console.error('Configuration file has syntax errors:');
        console.error(error.message);
        console.error('\nPlease fix the YAML syntax and try again.');
        process.exit(1);
      }

      // Security error
      if (error.message.includes('security check failed')) {
        console.error('Configuration security error:');
        console.error(error.message);
        process.exit(1);
      }
    }
    throw error;
  }
}
```

### Handling Audit Errors

```typescript
import { runAudit, EXIT_CODES } from 'pnpm-audit-hook';

async function safeAudit() {
  try {
    const result = await runAudit(lockfile, runtime);

    switch (result.exitCode) {
      case EXIT_CODES.SUCCESS:
        console.log('✅ No issues found');
        break;

      case EXIT_CODES.BLOCKED:
        console.error('🚫 Installation blocked');
        // Show blocked findings
        const blocked = result.decisions.filter(d => d.action === 'block');
        for (const d of blocked) {
          console.error(`  - ${d.packageName}: ${d.reason}`);
        }
        break;

      case EXIT_CODES.WARNINGS:
        console.warn('⚠️ Warnings present');
        break;

      case EXIT_CODES.SOURCE_ERROR:
        console.error('❌ Vulnerability source failed');
        for (const [name, status] of Object.entries(result.sourceStatus)) {
          if (!status.ok) {
            console.error(`  ${name}: ${status.error}`);
          }
        }
        break;
    }

    return result;
  } catch (error) {
    console.error('Audit failed unexpectedly:', error);
    process.exit(1);
  }
}
```
