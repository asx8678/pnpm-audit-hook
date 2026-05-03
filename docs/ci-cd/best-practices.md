# CI/CD Best Practices

This guide covers best practices for integrating pnpm-audit-hook into your CI/CD pipelines effectively and securely.

## Security Best Practices

### 1. Use Least Privilege Principle

**Why**: Limit the damage if credentials are compromised.

**How**:
```yaml
# GitHub Actions example
permissions:
  contents: read
  security-events: write  # Only if needed
```

```yaml
# Azure DevOps example
- task: AzureCLI@2
  inputs:
    azureSubscription: 'your-service-connection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
```

### 2. Secure Sensitive Data

**Why**: Prevent credential leaks and unauthorized access.

**How**:
```yaml
# Use environment secrets
- run: pnpm audit --token=$AUDIT_TOKEN
  env:
    AUDIT_TOKEN: ${{ secrets.AUDIT_TOKEN }}
```

```yaml
# Use encrypted variables
variables:
  - name: audit-token
    value: $(AUDIT_TOKEN)
    secret: true
```

### 3. Scan for Secrets

**Why**: Prevent accidental exposure of sensitive data.

**How**:
```yaml
- name: Secret Scanning
  run: |
    # Scan for potential secrets in code
    grep -r "password\|secret\|token\|key" . --include="*.ts" --include="*.js"
```

### 4. Validate Dependencies

**Why**: Ensure dependencies haven't been tampered with.

**How**:
```yaml
- name: Install Dependencies
  run: pnpm install --frozen-lockfile

- name: Verify Lockfile
  run: pnpm install --frozen-lockfile --prefer-offline
```

### 5. Use Signed Commits

**Why**: Ensure code integrity and authenticity.

**How**:
```yaml
- name: Verify Commit Signatures
  run: |
    git verify-commit $GITHUB_SHA
```

## Performance Best Practices

### 1. Cache Dependencies

**Why**: Speed up pipeline execution by avoiding repeated downloads.

**How**:
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
    - .pnpm-store/
```

### 2. Run Audits in Parallel

**Why**: Reduce overall pipeline execution time.

**How**:
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

### 3. Use Incremental Auditing

**Why**: Only audit changed packages for faster feedback.

**How**:
```yaml
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

### 4. Set Appropriate Timeouts

**Why**: Prevent hanging pipelines from consuming resources.

**How**:
```yaml
# GitHub Actions
jobs:
  audit:
    timeout-minutes: 15

# Azure DevOps
jobs:
  - job: Audit
    timeoutInMinutes: 15
```

### 5. Optimize Docker Images

**Why**: Reduce build time and resource usage.

**How**:
```yaml
# Use multi-stage builds
FROM node:20-slim AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile
COPY . .
RUN pnpm audit

FROM node:20-slim
COPY --from=builder /app .
```

## Reliability Best Practices

### 1. Fail Fast on Critical Issues

**Why**: Get immediate feedback on critical vulnerabilities.

**How**:
```yaml
- name: Security Audit
  run: |
    pnpm audit --severity=critical
    if [ $? -ne 0 ]; then
      echo "Critical vulnerabilities found"
      exit 1
    fi
```

### 2. Use Retry Logic

**Why**: Handle transient failures gracefully.

**How**:
```yaml
- name: Security Audit
  uses: nick-fields/retry@v2
  with:
    timeout_minutes: 10
    max_attempts: 3
    command: pnpm audit
```

### 3. Add Health Checks

**Why**: Ensure dependencies are available and working.

**How**:
```yaml
- name: Health Check
  run: |
    curl -f https://registry.npmjs.org/pnpm-audit-hook || exit 1
    pnpm audit
```

### 4. Monitor Pipeline Performance

**Why**: Identify bottlenecks and optimize.

**How**:
```yaml
- name: Measure Audit Time
  run: |
    start_time=$(date +%s)
    pnpm audit
    end_time=$(date +%s)
    echo "Audit took $((end_time - start_time)) seconds"
```

### 5. Use Idempotent Commands

**Why**: Ensure pipelines can be rerun safely.

**How**:
```yaml
- name: Clean Install
  run: |
    rm -rf node_modules
    pnpm install --frozen-lockfile
    pnpm audit
```

## Error Handling Best Practices

### 1. Set Exit Codes

**Why**: Enable conditional logic in your pipeline.

**How**:
```yaml
- name: Security Audit
  id: audit
  run: |
    pnpm audit
    echo "exit_code=$?" >> $GITHUB_OUTPUT

- name: Check Results
  if: steps.audit.outputs.exit_code != '0'
  run: echo "Audit failed"
```

### 2. Use Continue on Error

**Why**: Prevent non-critical issues from blocking pipelines.

**How**:
```yaml
- name: Security Audit
  continue-on-error: true
  run: pnpm audit
```

### 3. Provide Meaningful Error Messages

**Why**: Help developers understand and fix issues quickly.

**How**:
```yaml
- name: Security Audit
  run: |
    pnpm audit --output=json > audit-report.json
    BLOCKED=$(jq '.blocked' audit-report.json)
    if [ "$BLOCKED" == "true" ]; then
      echo "::error::Security audit failed - critical vulnerabilities found"
      echo "Please review the audit report for details"
      exit 1
    fi
```

### 4. Log Detailed Output

**Why**: Provide enough information for debugging.

**How**:
```yaml
- name: Security Audit
  run: |
    pnpm audit --output=human
    echo "Exit code: $?"
    echo "Environment: $CI_ENVIRONMENT"
```

### 5. Handle Partial Failures

**Why**: Ensure all relevant information is collected even if some steps fail.

**How**:
```yaml
- name: Security Audit
  id: audit
  run: pnpm audit
  continue-on-error: true

- name: Upload Report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: audit-report
    path: audit-report.json
```

## Maintainability Best Practices

### 1. Use Configuration Files

**Why**: Centralize configuration and avoid duplication.

**How**:
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

### 2. Version Control Pipelines

**Why**: Track changes and enable rollbacks.

**How**:
```bash
git add .github/workflows/security.yml
git commit -m "Update security audit pipeline"
git push
```

### 3. Use Templates and Reusable Workflows

**Why**: Reduce duplication and improve consistency.

**How**:
```yaml
# GitHub Actions reusable workflow
jobs:
  audit:
    uses: ./.github/workflows/security-audit.yml
    with:
      severity: high
```

### 4. Document Your Pipelines

**Why**: Help new team members understand the setup.

**How**:
```yaml
# Add comments to your pipeline
# This workflow runs security audits on every push and pull request
# It uses pnpm-audit-hook to detect vulnerabilities
name: Security Audit
on: [push, pull_request]
```

### 5. Regularly Update Dependencies

**Why**: Ensure you have the latest security patches.

**How**:
```yaml
- name: Update Dependencies
  run: |
    pnpm update
    pnpm audit
```

## Monitoring and Alerting

### 1. Set Up Notifications

**Why**: Get informed about security issues immediately.

**How**:
```yaml
- name: Notify on Failure
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: failure
    fields: repo,message,commit,author
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### 2. Track Metrics

**Why**: Monitor pipeline performance and security trends.

**How**:
```yaml
- name: Track Metrics
  run: |
    echo "Vulnerability count: $(jq '.findings | length' audit-report.json)"
    echo "Build duration: ${{ steps.duration.outputs.time }}"
```

### 3. Generate Reports

**Why**: Provide detailed information for analysis.

**How**:
```yaml
- name: Generate Report
  run: |
    pnpm audit --output=json > audit-report.json
    jq '.' audit-report.json > pretty-report.json
```

### 4. Integrate with Security Tools

**Why**: Centralize security monitoring and response.

**How**:
```yaml
- name: Send to SIEM
  run: |
    curl -X POST https://siem.company.com/api/events \
      -H "Content-Type: application/json" \
      -d @audit-report.json
```

## Platform-Specific Tips

### GitHub Actions

```yaml
# Use matrix strategy for multiple Node.js versions
strategy:
  matrix:
    node-version: [18, 20, 22]

# Use caching with setup-node
- uses: actions/setup-node@v4
  with:
    node-version: ${{ matrix.node-version }}
    cache: 'pnpm'
```

### Azure DevOps

```yaml
# Use task conditions
- script: pnpm audit
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))

# Use variable groups
variables:
  - group: security-audit-variables
```

### AWS CodeBuild

```yaml
# Use buildspec environment variables
env:
  variables:
    NODE_ENV: production
    AUDIT_SEVERITY: high

# Use reports
reports:
  audit-reports:
    files:
      - audit-report.json
    file-format: JSON
```

### GitLab CI

```yaml
# Use rules for conditional execution
rules:
  - if: $CI_COMMIT_BRANCH == "main"
  - if: $CI_PIPELINE_SOURCE == "merge_request_event"

# Use extends for DRY configuration
.security-audit:
  stage: security
  script:
    - pnpm audit
```

### Jenkins

```groovy
// Use pipeline syntax
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'pnpm audit'
            }
        }
    }
}

// Use environment variables
environment {
    NODE_ENV = 'production'
    AUDIT_SEVERITY = 'high'
}
```

## Common Pitfalls to Avoid

### 1. Don't Ignore Warnings

**Why**: Warnings can become critical over time.

**Solution**: Review and address warnings regularly.

### 2. Don't Hardcode Credentials

**Why**: Security risk if credentials are exposed.

**Solution**: Use secrets management and environment variables.

### 3. Don't Skip Audits

**Why**: Vulnerabilities can enter production undetected.

**Solution**: Make audits mandatory in your pipeline.

### 4. Don't Use Outdated Dependencies

**Why**: Old versions may have known vulnerabilities.

**Solution**: Regularly update dependencies and audit.

### 5. Don't Ignore Exit Codes

**Why**: Failed audits may not be caught.

**Solution**: Check exit codes and handle failures appropriately.

## Further Reading

- [Platform-Specific Guides](./github-actions.md)
- [Troubleshooting Guide](./troubleshooting.md)
- [Configuration Reference](../api/config.md)
- [Architecture Overview](../architecture/README.md)

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team