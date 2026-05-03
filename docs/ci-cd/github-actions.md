# GitHub Actions Integration

GitHub Actions is the recommended CI/CD platform for pnpm-audit-hook integration. It provides full support for annotations, log grouping, and output variables.

## Quick Start

### Basic Workflow

Create a new workflow file at `.github/workflows/security.yml`:

```yaml
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

### Step-by-Step Setup

1. **Create workflow directory**:
   ```bash
   mkdir -p .github/workflows
   ```

2. **Create workflow file**:
   ```bash
   touch .github/workflows/security.yml
   ```

3. **Add the workflow content** from the example above.

4. **Commit and push**:
   ```bash
   git add .github/workflows/security.yml
   git commit -m "Add security audit workflow"
   git push
   ```

## Features

### Annotations

pnpm-audit-hook automatically creates GitHub Actions annotations for vulnerabilities:

- **Error annotations** for critical/high severity vulnerabilities
- **Warning annotations** for medium/low severity vulnerabilities  
- **Notice annotations** for informational messages

These annotations appear directly in the GitHub UI, making it easy to identify security issues.

### Log Groups

The tool uses GitHub Actions log groups to organize output:

```
::group::Source Status
GitHub Advisory: OK (1234ms)
NVD: OK (2345ms)
::endgroup::

::group::Vulnerability Details
::error::[CRITICAL] GHSA-xxxx-xxxx-xxxx in lodash@4.17.20
  Title: Prototype Pollution in lodash
  URL: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
::endgroup::
```

### Output Variables

Set output variables for conditional workflow logic:

```yaml
- name: Security Audit
  id: audit
  run: pnpm audit --output=github

- name: Check Results
  run: |
    if [ "${{ steps.audit.outputs.blocked }}" == "true" ]; then
      echo "Audit failed - blocking deployment"
      exit 1
    fi
```

## Advanced Configuration

### Custom Configuration

Create a `.pnpm-audit-hook.yml` file in your project root:

```yaml
# .pnpm-audit-hook.yml
output: github
severity: high
ignore:
  - "npm:.*"
  - "CVE-2023-.*"
allowlist:
  - package: "example-package"
    reason: "Not used in production"
    expires: "2024-12-31"
```

### Multi-Platform Support

Test across multiple Node.js versions:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18, 20, 22]
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
      - run: pnpm install --frozen-lockfile
      - run: pnpm audit
```

### Caching Dependencies

Speed up your workflow with caching:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm audit
```

### Conditional Execution

Run audit only on specific conditions:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request' || github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - run: pnpm install --frozen-lockfile
      - run: pnpm audit
```

### Artifacts and Reporting

Generate and upload audit reports:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - run: pnpm install --frozen-lockfile
      
      - name: Run Audit
        run: pnpm audit --output=json > audit-report.json
        
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: audit-report.json
          
      - name: Parse Results
        if: always()
        run: |
          BLOCKED=$(jq '.blocked' audit-report.json)
          if [ "$BLOCKED" == "true" ]; then
            echo "::error::Security audit failed - deployment blocked"
            exit 1
          fi
```

### Notifications

Set up notifications for security issues:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - run: pnpm install --frozen-lockfile
      
      - name: Run Audit
        id: audit
        run: pnpm audit --output=github
        
      - name: Notify on Failure
        if: steps.audit.outputs.blocked == 'true'
        uses: 8398a7/action-slack@v3
        with:
          status: failure
          fields: repo,message,commit,author
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## Best Practices

### Security

1. **Use pinned actions**: Always pin to specific versions or SHA hashes
   ```yaml
   - uses: actions/checkout@v4  # Recommended
   # Instead of: - uses: actions/checkout@main
   ```

2. **Limit permissions**:
   ```yaml
   permissions:
     contents: read
     security-events: write  # For security alerts
   ```

3. **Use secrets** for sensitive configuration:
   ```yaml
   env:
     AUDIT_TOKEN: ${{ secrets.AUDIT_TOKEN }}
   ```

### Performance

1. **Cache dependencies** to avoid reinstalling
2. **Run audits in parallel** with other checks
3. **Use incremental auditing** for large projects
4. **Set appropriate timeouts** to prevent hanging

### Reliability

1. **Fail fast** on critical vulnerabilities
2. **Set exit codes** for conditional logic
3. **Use idempotent commands** to handle reruns
4. **Add retry logic** for transient failures

## Troubleshooting

### Common Issues

#### 1. Annotations not appearing

**Problem**: Vulnerability annotations don't show up in the GitHub UI.

**Solution**: Ensure you're using the correct output format:
```yaml
- run: pnpm audit --output=github
```

#### 2. Workflow fails on warnings

**Problem**: Workflow fails even for non-critical vulnerabilities.

**Solution**: Use the `continue-on-error` option:
```yaml
- name: Security Audit
  continue-on-error: true
  run: pnpm audit --output=github
```

#### 3. Slow workflow execution

**Problem**: Security audit takes too long.

**Solution**: Enable caching and optimize:
```yaml
- uses: actions/setup-node@v4
  with:
    node-version: '20'
    cache: 'pnpm'
```

#### 4. False positives

**Problem**: Audit reports vulnerabilities that don't affect your project.

**Solution**: Use the configuration file to ignore or allowlist:
```yaml
# .pnpm-audit-hook.yml
ignore:
  - "npm:.*"  # Ignore npm vulnerabilities
  - "CVE-2023-.*"  # Ignore specific CVEs
```

### Debugging

Enable debug logging to troubleshoot issues:

```yaml
- name: Run Audit
  run: pnpm audit --output=github --debug
  env:
    DEBUG: pnpm-audit-hook:*
```

### Getting Help

If you encounter issues:

1. Check the [GitHub Actions documentation](https://docs.github.com/en/actions)
2. Review the [pnpm-audit-hook troubleshooting guide](./troubleshooting.md)
3. Search [existing issues](https://github.com/pnpm/pnpm-audit-hook/issues)
4. Open a new issue with detailed logs

## Example Workflows

### Complete Production Workflow

```yaml
name: Production Security Audit
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security-audit:
    runs-on: ubuntu-latest
    outputs:
      blocked: ${{ steps.audit.outputs.blocked }}
      vulnerability-count: ${{ steps.audit.outputs.vulnerability-count }}
    steps:
      - uses: actions/checkout@v4
      
      - uses: pnpm/action-setup@v2
        with:
          version: 8
          
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
          
      - name: Install Dependencies
        run: pnpm install --frozen-lockfile
        
      - name: Run Security Audit
        id: audit
        run: pnpm audit --output=github
        
      - name: Upload Audit Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-report
          path: audit-report.json
          retention-days: 30
          
      - name: Fail on Critical Vulnerabilities
        if: steps.audit.outputs.blocked == 'true'
        run: |
          echo "::error::Security audit failed - critical vulnerabilities found"
          exit 1
          
  deployment:
    needs: security-audit
    runs-on: ubuntu-latest
    if: needs.security-audit.outputs.blocked != 'true'
    steps:
      - uses: actions/checkout@v4
      - name: Deploy Application
        run: ./deploy.sh
```

### Monorepo Workflow

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        package: ['frontend', 'backend', 'shared']
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
          
      - name: Install Dependencies
        run: pnpm install --frozen-lockfile
        
      - name: Audit ${{ matrix.package }}
        run: pnpm --filter ${{ matrix.package }} audit --output=github
```

## Further Reading

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [pnpm-audit-hook Configuration](../api/config.md)
- [Best Practices](./best-practices.md)
- [Troubleshooting Guide](./troubleshooting.md)

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team