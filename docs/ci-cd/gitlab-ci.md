# GitLab CI Integration

GitLab CI provides good integration with pnpm-audit-hook, with support for CI variables and job artifacts.

## Quick Start

### Basic Pipeline

Create a `.gitlab-ci.yml` file in your project root:

```yaml
stages:
  - security
  - build
  - deploy

security-audit:
  stage: security
  image: node:20
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm audit
  allow_failure: false
```

### Step-by-Step Setup

1. **Create pipeline file**:
   ```bash
   touch .gitlab-ci.yml
   ```

2. **Add the pipeline content** from the example above.

3. **Commit and push**:
   ```bash
   git add .gitlab-ci.yml
   git commit -m "Add GitLab CI security pipeline"
   git push
   ```

4. **Pipeline runs automatically** on push to your repository.

## Features

### CI Variables

GitLab CI supports setting variables for conditional logic:

```yaml
security-audit:
  stage: security
  script:
    - pnpm audit --output=json > audit-report.json
    - export AUDIT_BLOCKED=$(jq '.blocked' audit-report.json)
  variables:
    AUDIT_SEVERITY: high
```

### Artifacts

Generate and store audit reports:

```yaml
security-audit:
  stage: security
  script:
    - pnpm audit --output=json > audit-report.json
  artifacts:
    reports:
      - audit-report.json
    expire_in: 1 week
  artifacts:
    paths:
      - audit-report.json
```

### Merge Request Integration

Run security audits on merge requests:

```yaml
security-audit:
  stage: security
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - pnpm audit
```

## Advanced Configuration

### Custom Configuration

Create a `.pnpm-audit-hook.yml` file:

```yaml
# .pnpm-audit-hook.yml
output: human  # GitLab CI doesn't have specific formatting
severity: high
ignore:
  - "npm:.*"
  - "CVE-2023-.*"
allowlist:
  - package: "example-package"
    reason: "Not used in production"
    expires: "2024-12-31"
```

### Multi-Stage Pipeline

```yaml
stages:
  - security
  - build
  - test
  - deploy

security-audit:
  stage: security
  image: node:20
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm audit
  allow_failure: false

build:
  stage: build
  image: node:20
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm run build
  artifacts:
    paths:
      - dist/

test:
  stage: test
  image: node:20
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm test

deploy:
  stage: deploy
  image: alpine:latest
  script:
    - echo "Deploying application..."
  only:
    - main
```

### Caching

Enable caching for faster pipeline execution:

```yaml
security-audit:
  stage: security
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
      - .pnpm-store/
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm audit
```

### Conditional Execution

Run audit only on specific branches:

```yaml
security-audit:
  stage: security
  script:
    - pnpm audit
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_COMMIT_BRANCH == "develop"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Parallel Execution

Run audits in parallel for different packages:

```yaml
security-audit:frontend:
  stage: security
  script:
    - pnpm --filter frontend audit

security-audit:backend:
  stage: security
  script:
    - pnpm --filter backend audit

security-audit:shared:
  stage: security
  script:
    - pnpm --filter shared audit
```

### Artifacts and Reporting

Generate and publish audit reports:

```yaml
security-audit:
  stage: security
  script:
    - pnpm audit --output=json > audit-report.json
  artifacts:
    paths:
      - audit-report.json
    reports:
      - audit-report.json
    expire_in: 30 days
  allow_failure: false
```

### Notifications

Set up notifications for security issues:

```yaml
security-audit:
  stage: security
  script:
    - pnpm audit
  after_script:
    - |
      if [ "$CI_JOB_STATUS" == "failed" ]; then
        curl -X POST -H "Content-Type: application/json" \
          -d '{"text": "Security audit failed for project $CI_PROJECT_NAME"}' \
          $SLACK_WEBHOOK_URL
      fi
```

## Best Practices

### Security

1. **Use protected variables**:
   ```yaml
   variables:
     AUDIT_TOKEN: $AUDIT_TOKEN  # Protected in GitLab UI
   ```

2. **Limit pipeline permissions**:
   ```yaml
   security-audit:
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
   ```

3. **Use environment secrets**:
   ```yaml
   security-audit:
     environment:
       name: production
       url: https://example.com
   ```

### Performance

1. **Enable caching** for dependencies
2. **Use parallel jobs** for faster execution
3. **Set appropriate timeouts** to prevent hanging
4. **Use Docker layer caching**

### Reliability

1. **Fail fast** on critical vulnerabilities
2. **Use retry logic** for transient failures
3. **Add health checks** for dependencies
4. **Monitor pipeline performance**

## Troubleshooting

### Common Issues

#### 1. Pipeline fails on warnings

**Problem**: Pipeline fails even for non-critical vulnerabilities.

**Solution**: Use the `allow_failure` option:
```yaml
security-audit:
  allow_failure: true
  script:
    - pnpm audit
```

#### 2. Artifacts not available

**Problem**: Audit report artifacts aren't available after pipeline.

**Solution**: Check artifact paths and expiration:
```yaml
artifacts:
  paths:
    - audit-report.json
  expire_in: 1 week
```

#### 3. Caching not working

**Problem**: Dependencies aren't being cached properly.

**Solution**: Check cache configuration:
```yaml
cache:
  key:
    files:
      - pnpm-lock.yaml
  paths:
    - node_modules/
```

#### 4. Variables not set

**Problem**: Environment variables aren't available.

**Solution**: Check variable configuration in GitLab UI:
- Go to **Settings** > **CI/CD** > **Variables**
- Add your variables with appropriate protection

### Debugging

Enable debug logging:

```yaml
security-audit:
  script:
    - pnpm audit --debug
  variables:
    DEBUG: pnpm-audit-hook:*
```

### Getting Help

If you encounter issues:

1. Check the [GitLab CI documentation](https://docs.gitlab.com/ee/ci/)
2. Review the [pnpm-audit-hook troubleshooting guide](./troubleshooting.md)
3. Search [existing issues](https://github.com/pnpm/pnpm-audit-hook/issues)
4. Open a new issue with detailed logs

## Example Workflows

### Complete Production Pipeline

```yaml
stages:
  - security
  - build
  - test
  - deploy

variables:
  NODE_ENV: production
  AUDIT_SEVERITY: high

security-audit:
  stage: security
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
      - .pnpm-store/
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm audit --severity=$AUDIT_SEVERITY
  artifacts:
    paths:
      - audit-report.json
    reports:
      - audit-report.json
    expire_in: 30 days
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: false

build:
  stage: build
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
      - .pnpm-store/
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm run build
  artifacts:
    paths:
      - dist/
  only:
    - main
    - develop

test:
  stage: test
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
      - .pnpm-store/
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm test
  coverage: '/Lines\s*:\s*(\d+\.?\d*)%/'
  only:
    - main
    - develop

deploy:
  stage: deploy
  image: alpine:latest
  script:
    - echo "Deploying application..."
    - echo "Deploying to production environment"
  environment:
    name: production
    url: https://example.com
  only:
    - main
  when: manual
```

### Monorepo Pipeline

```yaml
stages:
  - security
  - build
  - test

.security-audit:
  stage: security
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
      - .pnpm-store/
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile

security-audit:frontend:
  extends: .security-audit
  script:
    - pnpm --filter frontend audit

security-audit:backend:
  extends: .security-audit
  script:
    - pnpm --filter backend audit

security-audit:shared:
  extends: .security-audit
  script:
    - pnpm --filter shared audit

.build:
  stage: build
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
      - .pnpm-store/
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile

build:frontend:
  extends: .build
  script:
    - pnpm --filter frontend build
  artifacts:
    paths:
      - packages/frontend/dist/

build:backend:
  extends: .build
  script:
    - pnpm --filter backend build
  artifacts:
    paths:
      - packages/backend/dist/

test:
  stage: test
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
      - .pnpm-store/
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm test
```

### Security Scanning Pipeline

```yaml
stages:
  - security
  - build

security-audit:
  stage: security
  image: node:20
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm audit --output=json > audit-report.json
    - |
      BLOCKED=$(jq '.blocked' audit-report.json)
      if [ "$BLOCKED" == "true" ]; then
        echo "Security audit failed - critical vulnerabilities found"
        exit 1
      fi
  artifacts:
    paths:
      - audit-report.json
    reports:
      - audit-report.json
  allow_failure: false

dependency-scan:
  stage: security
  image: python:3.9
  before_script:
    - pip install safety
  script:
    - safety check --json --output safety-report.json
  artifacts:
    paths:
      - safety-report.json
  allow_failure: true

build:
  stage: build
  image: node:20
  needs:
    - security-audit
    - dependency-scan
  before_script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
  script:
    - pnpm run build
```

## Integration with GitLab Features

### Merge Request Approval

```yaml
security-audit:
  stage: security
  script:
    - pnpm audit
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: false
```

### Protected Branches

```yaml
security-audit:
  stage: security
  script:
    - pnpm audit
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  environment:
    name: production
```

### GitLab Container Registry

```yaml
build-image:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
```

## Further Reading

- [GitLab CI Documentation](https://docs.gitlab.com/ee/ci/)
- [pnpm-audit-hook Configuration](../api/config.md)
- [Best Practices](./best-practices.md)
- [Troubleshooting Guide](./troubleshooting.md)

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team