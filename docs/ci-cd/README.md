# CI/CD Integration Guide

Welcome to the CI/CD integration documentation for pnpm-audit-hook! 🎉

This guide covers integrating security auditing into your CI/CD pipelines across different platforms. With proper CI/CD integration, you can automatically detect vulnerabilities, enforce security policies, and prevent vulnerable packages from entering your production environment.

## Overview

pnpm-audit-hook provides native integration with major CI/CD platforms, offering:

- **Platform-specific annotations** that appear in your pipeline interface
- **Automatic CI detection** with tailored output formatting  
- **Exit codes** that work with standard CI failure mechanisms
- **Artifact generation** for detailed vulnerability reports
- **Policy enforcement** with configurable blocking rules

## Supported Platforms

| Platform | Integration Level | Annotations | Log Groups | Output Variables |
|----------|------------------|-------------|------------|------------------|
| [GitHub Actions](./github-actions.md) | Full | ✅ | ✅ | ✅ |
| [Azure DevOps](./azure-devops.md) | Full | ✅ | ✅ | ✅ |
| [AWS CodeBuild](./aws-codebuild.md) | Full | ✅ | ✅ | ⚠️ Limited |
| [GitLab CI](./gitlab-ci.md) | Good | ⚠️ Limited | ❌ | ✅ |
| [Jenkins](./jenkins.md) | Basic | ⚠️ Limited | ❌ | ❌ |

## Quick Start

### 1. Basic Integration

The simplest way to integrate pnpm-audit-hook into your CI/CD pipeline is to add it to your existing workflow:

```yaml
# Example: Basic CI integration
- name: Security Audit
  run: pnpm audit
```

### 2. Platform-Specific Integration

Each platform has unique features. Choose your platform for detailed instructions:

- **[GitHub Actions](./github-actions.md)** - Recommended for open-source projects
- **[Azure DevOps](./azure-devops.md)** - Best for enterprise Microsoft environments
- **[AWS CodeBuild](./aws-codebuild.md)** - Ideal for AWS-native deployments
- **[GitLab CI](./gitlab-ci.md)** - Great for GitLab-hosted projects
- **[Jenkins](./jenkins.md)** - For self-hosted CI environments

### 3. Advanced Configuration

For advanced use cases, see our [Best Practices](./best-practices.md) guide.

## Core Concepts

### Exit Codes

pnpm-audit-hook uses standard exit codes to communicate audit results:

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| 0 | Audit passed | No action needed |
| 1 | Audit failed (vulnerabilities found) | Consider blocking deployment |
| 2 | Configuration error | Check your configuration |
| 3 | Runtime error | Check logs for details |

### Annotations

CI/CD annotations make vulnerability information visible in your pipeline interface:

- **Errors**: Critical/high severity vulnerabilities
- **Warnings**: Medium/low severity vulnerabilities  
- **Notices**: Informational messages about audit status

### Output Variables

Many platforms support setting output variables for conditional logic:

```yaml
# Example: Conditional deployment based on audit results
- name: Security Audit
  id: audit
  run: pnpm audit

- name: Deploy
  if: steps.audit.outputs.blocked != 'true'
  run: ./deploy.sh
```

## Best Practices

### Security Best Practices

1. **Run audits in parallel** with other checks to save time
2. **Use caching** for dependency installation and audit results
3. **Set up notifications** for critical vulnerabilities
4. **Implement gradual rollout** with canary deployments
5. **Use secret scanning** for sensitive configuration

### Performance Optimization

1. **Cache node_modules** to avoid reinstalling dependencies
2. **Use incremental auditing** for large projects
3. **Parallelize audit steps** where possible
4. **Limit audit scope** to relevant directories

### Error Handling

1. **Fail fast** on critical vulnerabilities
2. **Continue on warnings** for non-blocking checks
3. **Set appropriate exit codes** for conditional logic
4. **Log detailed output** for debugging

## Troubleshooting

### Common Issues

1. **Annotations not appearing**
   - Check platform-specific syntax
   - Verify CI environment variables
   - Ensure proper log formatting

2. **False positives**
   - Review vulnerability database sources
   - Configure allowlists for known safe packages
   - Update to latest audit database

3. **Performance issues**
   - Enable caching
   - Reduce audit scope
   - Use parallel execution

For detailed troubleshooting, see [Troubleshooting Guide](./troubleshooting.md).

## Configuration

### Basic Configuration

Create a `.pnpm-audit-hook.yml` file in your project root:

```yaml
# Basic configuration
output: github  # or azure, aws, human, json
severity: high  # minimum severity to report
```

### Advanced Configuration

```yaml
# Advanced configuration
output: github
severity: medium
ignore:
  - "npm:.*"  # Ignore all npm vulnerabilities
  - "CVE-2023-.*"  # Ignore specific CVEs
allowlist:
  - package: "example-package"
    reason: "Not used in production"
    expires: "2024-12-31"
```

## Examples

### Basic Workflow

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - run: pnpm install --frozen-lockfile
      - run: pnpm audit
```

### Advanced Workflow

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    outputs:
      blocked: ${{ steps.audit.outputs.blocked }}
      vulnerability-count: ${{ steps.audit.outputs.vulnerability-count }}
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - run: pnpm install --frozen-lockfile
      
      - name: Run Security Audit
        id: audit
        run: |
          pnpm audit --output=github
          echo "blocked=$?" >> $GITHUB_OUTPUT
          
      - name: Upload Audit Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: audit-report.json
```

## Further Reading

- [Platform-Specific Guides](./github-actions.md)
- [Best Practices](./best-practices.md)
- [Troubleshooting](./troubleshooting.md)
- [Configuration Reference](../api/config.md)
- [Architecture Overview](../architecture/README.md)

## Contributing

Found an issue with the CI/CD integration? Want to add support for another platform? Check out our [Contributor Guide](../architecture/contributor-guide.md) for how to get involved!

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team