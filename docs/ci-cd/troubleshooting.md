# CI/CD Troubleshooting Guide

This guide helps you diagnose and resolve common issues with pnpm-audit-hook CI/CD integration.

## Common Issues

### 1. Annotations Not Appearing

**Symptoms**:
- Vulnerability annotations don't show up in pipeline interface
- No error/warning markers in build logs

**Possible Causes**:
1. Wrong output format
2. Platform-specific syntax issues
3. CI environment variables not set

**Solutions**:

**GitHub Actions**:
```yaml
# Ensure you're using the correct output format
- run: pnpm audit --output=github
```

**Azure DevOps**:
```yaml
# Ensure you're using the correct output format
- script: pnpm audit --output=azure
```

**AWS CodeBuild**:
```yaml
# Ensure you're using the correct output format
- pnpm audit --output=aws
```

**GitLab CI/Jenkins**:
```yaml
# These platforms don't have specific formatting
- pnpm audit
```

### 2. Pipeline Fails on Warnings

**Symptoms**:
- Pipeline fails even for non-critical vulnerabilities
- Build marked as failed when only warnings exist

**Solutions**:

**GitHub Actions**:
```yaml
- name: Security Audit
  continue-on-error: true
  run: pnpm audit
```

**Azure DevOps**:
```yaml
- script: pnpm audit
  displayName: 'Security Audit'
  continueOnError: true
```

**AWS CodeBuild**:
```yaml
- pnpm audit || true
```

**GitLab CI**:
```yaml
security-audit:
  allow_failure: true
  script:
    - pnpm audit
```

**Jenkins**:
```groovy
stage('Security Audit') {
    steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
            sh 'pnpm audit'
        }
    }
}
```

### 3. Variables Not Set

**Symptoms**:
- Pipeline variables aren't being set by the audit
- Conditional logic doesn't work

**Solutions**:

**GitHub Actions**:
```yaml
- name: Security Audit
  id: audit
  run: pnpm audit --output=github

- name: Check Results
  run: echo "Blocked: ${{ steps.audit.outputs.blocked }}"
```

**Azure DevOps**:
```yaml
- script: pnpm audit --output=azure
  displayName: 'Security Audit'

- script: echo "AUDIT_BLOCKED=$(AUDIT_BLOCKED)"
  displayName: 'Check Variables'
```

**AWS CodeBuild**:
```yaml
- pnpm audit --output=aws
- echo "AUDIT_BLOCKED=$(AUDIT_BLOCKED)"
```

### 4. Slow Pipeline Execution

**Symptoms**:
- Security audit takes too long
- Pipeline timeout occurs

**Solutions**:

**Enable Caching**:
```yaml
# GitHub Actions
- uses: actions/setup-node@v4
  with:
    node-version: '20'
    cache: 'pnpm'

# Azure DevOps
- task: Cache@2
  inputs:
    key: 'pnpm | "lock.json"'
    restoreKeys: |
      pnpm
    path: ~/.pnpm-store

# GitLab CI
cache:
  key:
    files:
      - pnpm-lock.yaml
  paths:
    - node_modules/
```

**Reduce Scope**:
```yaml
# Audit only changed packages
- name: Get Changed Files
  id: changed-files
  uses: tj-actions/changed-files@v42

- name: Audit Changed Packages
  run: |
    for file in ${{ steps.changed-files.outputs.all_changed_files }}; do
      if [[ $file == package.json ]]; then
        pnpm audit
      fi
    done
```

**Use Parallel Execution**:
```yaml
# GitHub Actions matrix strategy
jobs:
  audit:
    strategy:
      matrix:
        package: ['frontend', 'backend', 'shared']
    steps:
      - run: pnpm --filter ${{ matrix.package }} audit
```

### 5. False Positives

**Symptoms**:
- Audit reports vulnerabilities that don't affect your project
- Known safe packages flagged as vulnerable

**Solutions**:

**Configure Allowlist**:
```yaml
# .pnpm-audit-hook.yml
allowlist:
  - package: "example-package"
    reason: "Not used in production"
    expires: "2024-12-31"
  - package: "another-package"
    reason: "Already patched in our fork"
```

**Ignore Specific CVEs**:
```yaml
# .pnpm-audit-hook.yml
ignore:
  - "CVE-2023-.*"  # Ignore all 2023 CVEs
  - "GHSA-xxxx-xxxx-xxxx"  # Ignore specific advisory
```

**Update Vulnerability Database**:
```bash
# Force update of vulnerability database
pnpm audit --update-db
```

### 6. Memory Issues

**Symptoms**:
- Build fails with out-of-memory errors
- Process killed by OS

**Solutions**:

**Increase Node.js Memory**:
```yaml
- name: Security Audit
  run: NODE_OPTIONS="--max-old-space-size=4096" pnpm audit
```

**Increase Build Memory**:
```yaml
# AWS CodeBuild
phases:
  build:
    commands:
      - NODE_OPTIONS="--max-old-space-size=8192" pnpm audit
```

**Optimize for Large Projects**:
```yaml
- name: Security Audit
  run: |
    # Audit in batches
    pnpm --filter frontend audit
    pnpm --filter backend audit
    pnpm --filter shared audit
```

### 7. Network Issues

**Symptoms**:
- Audit fails to connect to vulnerability databases
- Timeouts when fetching advisories

**Solutions**:

**Retry Logic**:
```yaml
# GitHub Actions
- name: Security Audit
  uses: nick-fields/retry@v2
  with:
    timeout_minutes: 10
    max_attempts: 3
    command: pnpm audit
```

**Use Offline Mode**:
```yaml
- name: Security Audit
  run: pnpm audit --offline
```

**Configure Proxy**:
```yaml
- name: Security Audit
  env:
    HTTP_PROXY: ${{ secrets.HTTP_PROXY }}
    HTTPS_PROXY: ${{ secrets.HTTPS_PROXY }}
  run: pnpm audit
```

### 8. Permission Issues

**Symptoms**:
- Audit fails with permission denied errors
- Can't write audit reports

**Solutions**:

**Check File Permissions**:
```yaml
- name: Security Audit
  run: |
    chmod +x node_modules/.bin/pnpm-audit-hook
    pnpm audit
```

**Use Appropriate User**:
```yaml
# Docker
FROM node:20
RUN useradd -m audit-user
USER audit-user
```

**Fix Directory Permissions**:
```yaml
- name: Security Audit
  run: |
    mkdir -p reports
    chmod 777 reports
    pnpm audit --output-dir=reports
```

## Debugging Techniques

### 1. Enable Debug Logging

```yaml
- name: Security Audit
  run: pnpm audit --debug
  env:
    DEBUG: pnpm-audit-hook:*
```

### 2. Verbose Output

```yaml
- name: Security Audit
  run: pnpm audit --verbose
```

### 3. Check Environment Variables

```yaml
- name: Debug Environment
  run: |
    echo "CI: $CI"
    echo "GITHUB_ACTIONS: $GITHUB_ACTIONS"
    echo "TF_BUILD: $TF_BUILD"
    echo "CODEBUILD_BUILD_ID: $CODEBUILD_BUILD_ID"
```

### 4. Test Locally

```bash
# Simulate CI environment
CI=true pnpm audit

# Test with specific output format
pnpm audit --output=github > /dev/null
```

### 5. Inspect Audit Report

```yaml
- name: Security Audit
  run: |
    pnpm audit --output=json > audit-report.json
    jq '.' audit-report.json
    cat audit-report.json
```

## Error Messages and Solutions

### "Command failed with exit code 1"

**Cause**: Audit found vulnerabilities
**Solution**: Review audit report and address issues

### "Command failed with exit code 2"

**Cause**: Configuration error
**Solution**: Check your `.pnpm-audit-hook.yml` file

### "Command failed with exit code 3"

**Cause**: Runtime error
**Solution**: Check logs for specific error messages

### "ENOSPC: no space left on device"

**Cause**: Disk space issue
**Solution**: Clean up workspace or increase disk space

### "ECONNREFUSED: Connection refused"

**Cause**: Network connectivity issue
**Solution**: Check network settings and firewall rules

### "ETIMEOUT: Operation timed out"

**Cause**: Network timeout
**Solution**: Increase timeout or check network stability

## Platform-Specific Issues

### GitHub Actions

**Issue**: Annotations not showing in PR
**Solution**: Ensure you're using `::error::` and `::warning::` syntax

**Issue**: Output variables not set
**Solution**: Use `>> $GITHUB_OUTPUT` syntax

### Azure DevOps

**Issue**: Logging commands not working
**Solution**: Ensure you're using `##vso[task.logissue]` syntax

**Issue**: Variables not accessible
**Solution**: Use `$(variableName)` syntax in subsequent steps

### AWS CodeBuild

**Issue**: Reports not publishing
**Solution**: Check report configuration and file paths

**Issue**: Artifacts not available
**Solution**: Verify artifact paths and names

### GitLab CI

**Issue**: Artifacts not available after pipeline
**Solution**: Check artifact paths and expiration settings

**Issue**: Variables not protected
**Solution**: Mark variables as protected in GitLab UI

### Jenkins

**Issue**: Workspace corruption
**Solution**: Use `cleanWs()` step

**Issue**: Node.js version issues
**Solution**: Use NodeJS plugin or nvm

## Performance Issues

### 1. Slow Audit Execution

**Diagnosis**:
```yaml
- name: Measure Audit Time
  run: |
    start_time=$(date +%s)
    pnpm audit
    end_time=$(date +%s)
    echo "Audit took $((end_time - start_time)) seconds"
```

**Solutions**:
1. Enable caching
2. Use parallel execution
3. Reduce audit scope
4. Use faster network connection

### 2. High Memory Usage

**Diagnosis**:
```yaml
- name: Monitor Memory
  run: |
    free -h
    top -bn1 | head -20
```

**Solutions**:
1. Increase Node.js memory limit
2. Audit in smaller batches
3. Use swap space
4. Optimize for large projects

### 3. Network Bottlenecks

**Diagnosis**:
```yaml
- name: Test Network
  run: |
    curl -I https://registry.npmjs.org
    ping -c 5 registry.npmjs.org
```

**Solutions**:
1. Use local mirror
2. Enable caching
3. Use faster network connection
4. Audit offline when possible

## Getting Help

### 1. Check Logs

Always start by checking the full build logs for error messages.

### 2. Reproduce Locally

Try to reproduce the issue locally:
```bash
CI=true pnpm audit --debug
```

### 3. Search Existing Issues

Check if the issue has been reported before:
- [GitHub Issues](https://github.com/pnpm/pnpm-audit-hook/issues)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/pnpm-audit-hook)

### 4. Open New Issue

If you can't find a solution, open a new issue with:
- Complete error logs
- Steps to reproduce
- Platform and version information
- Configuration files

### 5. Community Support

Join the community for help:
- [GitHub Discussions](https://github.com/pnpm/pnpm-audit-hook/discussions)
- [Discord](https://discord.gg/pnpm-audit-hook)
- [Twitter](https://twitter.com/pnpm-audit-hook)

## Further Reading

- [Platform-Specific Guides](./github-actions.md)
- [Best Practices](./best-practices.md)
- [Configuration Reference](../api/config.md)
- [Architecture Overview](../architecture/README.md)

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team