# Contributor Guide

Welcome to the `pnpm-audit-hook` contributor guide! This document will help you get started with contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Structure](#code-structure)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Architecture Overview](#architecture-overview)
- [Common Tasks](#common-tasks)
- [Getting Help](#getting-help)

---

## Getting Started

### Prerequisites

- **Node.js**: >= 18.0.0
- **pnpm**: >= 8.0.0 (for package management)
- **Git**: Latest version
- **TypeScript**: Basic understanding

### First Steps

1. **Fork the repository**
   ```bash
   # Visit https://github.com/asx8678/pnpm-audit-hook
   # Click "Fork" button
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/pnpm-audit-hook.git
   cd pnpm-audit-hook
   ```

3. **Install dependencies**
   ```bash
   pnpm install
   ```

4. **Verify setup**
   ```bash
   pnpm run build
   pnpm test
   ```

---

## Development Setup

### Environment Configuration

Create a `.env.local` file for local development:

```bash
# GitHub token for API testing (optional)
GITHUB_TOKEN=ghp_xxxxx

# NVD API key (optional)
NVD_API_KEY=your-key

# Debug logging
PNPM_AUDIT_LOG_LEVEL=debug
```

### IDE Setup

**VS Code** (recommended):

1. Install extensions:
   - TypeScript Nightly
   - ESLint
   - Prettier

2. Use workspace settings:
   ```json
   {
     "editor.formatOnSave": true,
     "editor.defaultFormatter": "esbenp.prettier-vscode",
     "typescript.tsdk": "node_modules/typescript/lib"
   }
   ```

### Build Commands

```bash
# Full build (compile + copy static DB + bundle)
pnpm run build

# TypeScript compilation only
npx tsc -p tsconfig.json

# Watch mode for development
npx tsc -p tsconfig.json --watch
```

---

## Code Structure

### Directory Overview

```
pnpm-audit-hook/
├── src/                    # Source code
│   ├── index.ts           # Main entry point
│   ├── audit.ts           # Core audit logic
│   ├── config.ts          # Configuration handling
│   ├── types.ts           # TypeScript definitions
│   ├── databases/         # Vulnerability sources
│   ├── policies/          # Policy engine
│   ├── utils/             # Shared utilities
│   ├── cache/             # Caching layer
│   └── static-db/         # Offline database
├── test/                   # Test suite
├── bin/                   # CLI entry points
├── scripts/               # Build scripts
└── docs/                  # Documentation
```

### Key Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Public API and pnpm hooks |
| `src/audit.ts` | Core audit orchestration |
| `src/config.ts` | YAML config loading |
| `src/types.ts` | All TypeScript interfaces |
| `src/databases/aggregator.ts` | Multi-source coordination |
| `src/policies/policy-engine.ts` | Policy evaluation |

### Adding New Files

1. **Source files**: Place in appropriate `src/` subdirectory
2. **Tests**: Mirror structure in `test/`
3. **Utilities**: Add to `src/utils/`
4. **Types**: Export from `src/types.ts`

---

## Coding Standards

### TypeScript Style

```typescript
// ✅ Good: Explicit types
function processFindings(findings: VulnerabilityFinding[]): PolicyDecision[] {
  return findings.map(f => evaluateFinding(f));
}

// ❌ Bad: Implicit any
function processFindings(findings) {
  return findings.map(f => evaluateFinding(f));
}
```

### Naming Conventions

```typescript
// Types/Interfaces: PascalCase
interface VulnerabilityFinding { }
type Severity = 'critical' | 'high';

// Functions: camelCase
function evaluatePackagePolicies() { }

// Constants: UPPER_SNAKE_CASE
const CACHE_TTL_SECONDS = 3600;

// Files: kebab-case
// policy-engine.ts, vulnerability-finding.ts
```

### Code Organization

```typescript
// 1. Imports (external, then internal)
import path from 'node:path';
import type { AuditConfig } from '../types';
import { logger } from '../utils/logger';

// 2. Constants
const MAX_RETRIES = 3;
const TIMEOUT_MS = 15000;

// 3. Types/Interfaces
interface ProcessOptions {
  timeout: number;
  retries: number;
}

// 4. Main exports
export async function processData(
  input: string,
  options: ProcessOptions
): Promise<Result> {
  // Implementation
}

// 5. Internal functions
function validateInput(input: string): boolean {
  // Implementation
}
```

### Error Handling

```typescript
// ✅ Good: Typed errors with context
class ConfigError extends Error {
  constructor(
    message: string,
    public readonly path: string,
    public readonly line?: number
  ) {
    super(message);
    this.name = 'ConfigError';
  }
}

// ✅ Good: Result pattern for recoverable errors
async function querySource(): Promise<Result<VulnerabilityFinding[], HttpError>> {
  try {
    const findings = await fetchFindings();
    return { ok: true, value: findings };
  } catch (error) {
    return { ok: false, error: error as HttpError };
  }
}

// ❌ Bad: Throwing without context
function parse() {
  throw new Error('Invalid');
}
```

### Comments and Documentation

```typescript
/**
 * Evaluates vulnerability findings against configured policies.
 *
 * @param findings - Array of vulnerability findings to evaluate
 * @param config - Audit configuration with policy rules
 * @param graph - Optional dependency graph for direct-only checks
 * @returns Array of policy decisions (block/warn/allow)
 *
 * @example
 * ```typescript
 * const decisions = evaluatePackagePolicies(findings, config, graph);
 * const blocked = decisions.filter(d => d.action === 'block');
 * ```
 */
export function evaluatePackagePolicies(
  findings: VulnerabilityFinding[],
  config: AuditConfig,
  graph?: DependencyGraph
): PolicyDecision[] {
  // Implementation
}
```

---

## Testing Guidelines

### Running Tests

```bash
# All tests
pnpm test

# Unit tests only (fast)
pnpm run test:unit

# Integration tests
pnpm run test:integration

# Specific test file
node --import tsx --test test/config.test.ts

# With coverage
node --import tsx --test --experimental-test-coverage test/**/*.test.ts
```

### Test Structure

```typescript
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

describe('PolicyEngine', () => {
  let engine: PolicyEngine;
  
  beforeEach(() => {
    engine = new PolicyEngine();
  });
  
  describe('evaluatePackagePolicies', () => {
    it('should block critical vulnerabilities', () => {
      // Arrange
      const findings = [
        { id: 'CVE-123', severity: 'critical', packageName: 'vuln-pkg' }
      ];
      const config = { policy: { block: ['critical'] } };
      
      // Act
      const decisions = engine.evaluatePackagePolicies(findings, config);
      
      // Assert
      assert.equal(decisions.length, 1);
      assert.equal(decisions[0].action, 'block');
    });
    
    it('should allow findings matching allowlist', () => {
      // Test implementation
    });
  });
});
```

### Test Categories

1. **Unit Tests**: Test individual functions
   - Location: `test/*.test.ts`
   - Speed: Fast (< 1s)
   - Dependencies: None

2. **Integration Tests**: Test component interaction
   - Location: `test/integration/`
   - Speed: Medium (1-5s)
   - Dependencies: May need API keys

3. **End-to-End Tests**: Test full audit flow
   - Location: `test/integration/cli/`
   - Speed: Slow (5-30s)
   - Dependencies: pnpm installation

### Writing Good Tests

```typescript
// ✅ Good: Clear AAA pattern
it('should deduplicate findings across sources', () => {
  // Arrange
  const findings = [
    { id: 'CVE-1', packageName: 'pkg', source: 'github' },
    { id: 'CVE-1', packageName: 'pkg', source: 'nvd' },
  ];
  
  // Act
  const deduped = deduplicateFindings(findings);
  
  // Assert
  assert.equal(deduped.length, 1);
});

// ✅ Good: Descriptive test names
it('should return empty array when no packages in lockfile', () => {
  // Test implementation
});

// ❌ Bad: Unclear test name
it('works', () => {
  // Test implementation
});
```

### Test Fixtures

Use fixtures for complex test data:

```typescript
// test/fixtures/lockfiles.ts
export const basicLockfile = {
  lockfileVersion: '9.0',
  packages: {
    '/lodash@4.17.21': {
      resolution: { integrity: 'sha512-...' },
    },
  },
};

// In test
import { basicLockfile } from './fixtures/lockfiles';

it('should extract packages from lockfile', () => {
  const packages = extractPackagesFromLockfile(basicLockfile, defaultConfig);
  assert.equal(packages.length, 1);
});
```

---

## Documentation

### When to Document

- **New features**: Add to README and relevant docs
- **API changes**: Update JSDoc comments
- **Architecture changes**: Update architecture docs
- **Complex logic**: Add inline comments

### Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | User-facing overview |
| `docs/architecture/` | Technical deep dives |
| `docs/troubleshooting.md` | Common issues |
| `src/**/*.ts` | JSDoc in source |

### JSDoc Standards

```typescript
/**
 * Brief description of the function.
 *
 * Longer description if needed, explaining behavior,
 * edge cases, and important details.
 *
 * @param paramName - Description of parameter
 * @param optionalParam - Optional parameter description
 * @returns Description of return value
 * @throws {ErrorType} When condition is met
 *
 * @example
 * ```typescript
 * const result = functionName('input');
 * ```
 *
 * @see {@link relatedFunction} for related functionality
 * @since 1.0.0
 */
export function functionName(
  paramName: string,
  optionalParam?: number
): ReturnType {
  // Implementation
}
```

---

## Pull Request Process

### Before Creating PR

1. **Create an issue** for large changes
2. **Fork and branch** from `main`
3. **Write tests** for new functionality
4. **Update documentation** as needed
5. **Run full test suite**

### PR Checklist

```markdown
## Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
- [ ] TypeScript compiles without errors
- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] Commit messages are clear
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: <type>(<scope>): <description>

# Features
feat(config): add support for TOML configuration
feat(sources): implement new vulnerability source

# Bug fixes
fix(policy): handle expired allowlist entries correctly
fix(lockfile): parse v9 workspace protocol

# Documentation
docs(architecture): add ADR for caching strategy

# Refactoring
refactor(sources): extract common HTTP logic

# Tests
test(policy): add edge case coverage for allowlist

# Maintenance
chore(deps): update semver to 7.7.3
ci(github): add Node.js 22 to test matrix
```

### PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Refactoring

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests (if applicable)
- [ ] Manual testing performed

## Checklist

- [ ] Code follows project style
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Tests pass locally
```

### Review Process

1. **Automated checks** must pass
2. **At least one review** required
3. **Address feedback** promptly
4. **Squash and merge** to main

---

## Architecture Overview

For detailed architecture documentation, see:
- [Architecture README](./README.md)
- [Components](./components.md)
- [Data Flow](./data-flow.md)
- [Design Decisions](./decisions.md)
- [Design Patterns](./patterns.md)

### Key Concepts

1. **Hook System**: Integrates with pnpm's lifecycle
2. **Audit Engine**: Orchestrates the entire process
3. **Vulnerability Sources**: Pluggable data providers
4. **Policy Engine**: Evaluates findings against rules
5. **Output Formatters**: Platform-specific output

---

## Common Tasks

### Adding a New Vulnerability Source

1. Create `src/databases/my-source.ts`:

```typescript
import type { VulnerabilitySource, SourceContext, SourceResult } from './connector';

export class MySource implements VulnerabilitySource {
  id = 'my-source' as const;
  
  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.mySource?.enabled !== false;
  }
  
  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const startTime = Date.now();
    
    try {
      const findings = await this.fetchFindings(pkgs, ctx);
      return {
        source: this.id,
        ok: true,
        findings,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        source: this.id,
        ok: false,
        error: errorMessage(error),
        findings: [],
        durationMs: Date.now() - startTime,
      };
    }
  }
  
  private async fetchFindings(pkgs: PackageRef[], ctx: SourceContext): Promise<VulnerabilityFinding[]> {
    // Implementation
  }
}
```

2. Register in `src/databases/aggregator.ts`:

```typescript
import { MySource } from './my-source';

const sources = [
  new GitHubAdvisorySource(),
  new OsvSource(),
  new MySource(),  // Add here
];
```

3. Add config support in `src/types.ts`:

```typescript
interface AuditConfig {
  sources: {
    mySource?: {
      enabled?: boolean;
      apiKey?: string;
    };
  };
}
```

4. Write tests in `test/databases/my-source.test.ts`

### Adding a New Output Format

1. Create `src/utils/formatters/my-format.ts`:

```typescript
import type { AuditOutputData } from '../output-formatter';

export function formatMyPlatform(data: AuditOutputData): string {
  const lines: string[] = [];
  
  // Platform-specific formatting
  for (const finding of data.findings) {
    lines.push(`[${finding.severity}] ${finding.packageName}: ${finding.title}`);
  }
  
  return lines.join('\n');
}
```

2. Register in `src/utils/output-formatter.ts`:

```typescript
import { formatMyPlatform } from './formatters/my-format';

function getFormatter(format: OutputFormat): (data: AuditOutputData) => string {
  switch (format) {
    case 'github-actions':
      return formatGitHubActions;
    case 'my-platform':
      return formatMyPlatform;
    // ...
  }
}
```

3. Add environment detection:

```typescript
function getOutputFormatFromEnv(env: Record<string, string | undefined>): OutputFormat {
  if (env.MY_PLATFORM) return 'my-platform';
  // ...
}
```

### Adding a New Policy Rule

1. Extend `src/types.ts`:

```typescript
interface AuditConfig {
  policy: {
    block: Severity[];
    warn: Severity[];
    // New rule
    ignoreDevDependencies?: boolean;
  };
}
```

2. Implement in `src/policies/policy-engine.ts`:

```typescript
export function evaluatePackagePolicies(
  findings: VulnerabilityFinding[],
  config: AuditConfig,
  graph?: DependencyGraph
): PolicyDecision[] {
  return findings.map(finding => {
    // Existing logic...
    
    // New rule
    if (config.policy.ignoreDevDependencies && isDevDependency(finding, graph)) {
      return {
        findingId: finding.id,
        action: 'allow',
        source: 'policy',
        reason: 'Dev dependency ignored by policy',
      };
    }
    
    // ...
  });
}
```

3. Add tests:

```typescript
it('should ignore dev dependencies when configured', () => {
  const findings = [
    { id: 'CVE-1', packageName: 'dev-pkg', isDev: true }
  ];
  const config = {
    policy: { ignoreDevDependencies: true }
  };
  
  const decisions = evaluatePackagePolicies(findings, config, graph);
  assert.equal(decisions[0].action, 'allow');
});
```

---

## Getting Help

### Resources

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and ideas
- **Documentation**: In `docs/` directory
- **Code Comments**: Inline documentation

### Communication

- **Be respectful** and constructive
- **Provide context** in issues/PRs
- **Search first** for existing issues
- **Follow up** on your contributions

### Getting Unblocked

1. **Read the docs**: Check architecture docs
2. **Search issues**: Someone may have solved it
3. **Ask in discussions**: Community may help
4. **Tag maintainers**: For urgent issues

---

## Thank You!

Thank you for contributing to `pnpm-audit-hook`! Your help makes the project better for everyone.

Remember:
- Start small with issues labeled `good-first-issue`
- Ask questions if unsure
- Have fun and learn something new!

🐶 **Happy coding!**