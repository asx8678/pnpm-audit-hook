# Contributing to pnpm-audit-hook

Thank you for your interest in contributing to `pnpm-audit-hook`! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

---

## Getting Started

### Prerequisites

- **Node.js**: >= 18.0.0
- **pnpm**: >= 8.0.0
- **Git**: Latest version

### Quick Start

```bash
# Fork the repository on GitHub
git clone https://github.com/YOUR_USERNAME/pnpm-audit-hook.git
cd pnpm-audit-hook
pnpm install
pnpm run build
pnpm test
```

---

## Development Setup

### Environment Variables

Create a `.env.local` file for local development:

```bash
# Optional: GitHub token for API testing
GITHUB_TOKEN=ghp_xxxxx

# Optional: NVD API key
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

2. Use workspace settings (auto-configured via `.vscode/settings.json`)

### Build Commands

```bash
# Full build
pnpm run build

# TypeScript compilation only
npx tsc -p tsconfig.json

# Watch mode
npx tsc -p tsconfig.json --watch

# Run tests
pnpm test
```

---

## How to Contribute

### Types of Contributions

1. **Bug Fixes**: Fix issues in existing functionality
2. **Features**: Add new functionality
3. **Documentation**: Improve docs and examples
4. **Tests**: Add or improve test coverage
5. **Refactoring**: Improve code quality without changing behavior

### Finding Issues

- Check [GitHub Issues](https://github.com/asx8678/pnpm-audit-hook/issues) for open issues
- Look for issues labeled `good-first-issue` for beginners
- Feel free to ask questions in discussions

### Creating Issues

When creating a new issue:

1. **Bug reports**: Include reproduction steps, expected vs actual behavior
2. **Feature requests**: Explain the use case and proposed solution
3. **Questions**: Use GitHub Discussions for general questions

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

- **Types/Interfaces**: `PascalCase` (`VulnerabilityFinding`)
- **Functions**: `camelCase` (`evaluatePackagePolicies`)
- **Constants**: `UPPER_SNAKE_CASE` (`CACHE_TTL_SECONDS`)
- **Files**: `kebab-case` (`policy-engine.ts`)

### Code Organization

```typescript
// 1. Imports (external, then internal)
import path from 'node:path';
import type { AuditConfig } from '../types';
import { logger } from '../utils/logger';

// 2. Constants
const MAX_RETRIES = 3;

// 3. Types/Interfaces
interface ProcessOptions {
  timeout: number;
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

### Documentation

- Use JSDoc for all public functions
- Add comments for complex logic
- Update documentation when changing behavior

---

## Testing

### Running Tests

```bash
# All tests
pnpm test

# Unit tests only
pnpm run test:unit

# Integration tests
pnpm run test:integration

# Specific test file
node --import tsx --test test/config.test.ts
```

### Writing Tests

```typescript
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

describe('PolicyEngine', () => {
  let engine: PolicyEngine;
  
  beforeEach(() => {
    engine = new PolicyEngine();
  });
  
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
});
```

### Test Coverage

- Aim for comprehensive coverage of new features
- Test edge cases and error conditions
- Integration tests for component interaction

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

### Architecture Documentation

For detailed architecture information, see:
- [Architecture Overview](docs/architecture/README.md)
- [Component Details](docs/architecture/components.md)
- [Data Flow](docs/architecture/data-flow.md)
- [Design Decisions](docs/architecture/decisions.md)
- [Design Patterns](docs/architecture/patterns.md)

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

# Documentation
docs(architecture): add ADR for caching strategy

# Refactoring
refactor(sources): extract common HTTP logic

# Tests
test(policy): add edge case coverage for allowlist
```

### Review Process

1. **Automated checks** must pass
2. **At least one review** required
3. **Address feedback** promptly
4. **Squash and merge** to main

---

## Community

### Communication

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and ideas
- **Pull Requests**: For code contributions

### Code of Conduct

- Be respectful and constructive
- Provide context in issues/PRs
- Search first for existing issues
- Follow up on your contributions

### Getting Help

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