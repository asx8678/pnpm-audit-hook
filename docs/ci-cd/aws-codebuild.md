# AWS CodeBuild Integration

AWS CodeBuild provides good integration with pnpm-audit-hook, with support for log grouping and annotations through CloudWatch Logs.

## Quick Start

### Basic Buildspec

Create a `buildspec.yml` file in your project root:

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - pnpm audit
```

### Step-by-Step Setup

1. **Create buildspec file**:
   ```bash
   touch buildspec.yml
   ```

2. **Add the buildspec content** from the example above.

3. **Commit and push**:
   ```bash
   git add buildspec.yml
   git commit -m "Add AWS CodeBuild security spec"
   git push
   ```

4. **Create CodeBuild project**:
   - Go to AWS Console > CodeBuild > Create build project
   - Connect your repository
   - Set the buildspec location to "Use a buildspec file"
   - Create the project

## Features

### Log Grouping

pnpm-audit-hook uses CloudWatch Logs formatting:

```
##[group]Source Status
GitHub Advisory: OK (1234ms)
NVD: OK (2345ms)
##[endgroup]

##[group]Vulnerability Details
[ERROR] [CRITICAL] GHSA-xxxx-xxxx-xxxx in lodash@4.17.20
##[endgroup]
```

### Annotations

The tool creates log-based annotations:

```
[WARNING] npm:lodash@4.17.20: Prototype Pollution in lodash
[ERROR] [CRITICAL] GHSA-xxxx-xxxx-xxxx in lodash@4.17.20
```

### Build Status

CodeBuild uses exit codes to determine build status:

- **Exit code 0**: Build succeeded
- **Exit code 1**: Build failed (vulnerabilities found)
- **Exit code non-zero**: Build failed

## Advanced Configuration

### Custom Configuration

Create a `.pnpm-audit-hook.yml` file:

```yaml
# .pnpm-audit-hook.yml
output: aws
severity: high
ignore:
  - "npm:.*"
  - "CVE-2023-.*"
allowlist:
  - package: "example-package"
    reason: "Not used in production"
    expires: "2024-12-31"
```

### Multi-Stage Build

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  pre_build:
    commands:
      - echo "Running security audit..."
      - pnpm audit --output=aws
  build:
    commands:
      - echo "Building application..."
      - pnpm run build
  post_build:
    commands:
      - echo "Security audit completed"
```

### Environment Variables

Use environment variables for configuration:

```yaml
version: 0.2

env:
  variables:
    NODE_ENV: production
    AUDIT_SEVERITY: high

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - pnpm audit --output=aws --severity=$AUDIT_SEVERITY
```

### Artifacts

Generate and store audit reports:

```yaml
version: 0.2

artifacts:
  files:
    - audit-report.json
  discard-paths: yes
  name: audit-report

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - pnpm audit --output=json > audit-report.json
```

### Caching

Enable caching for faster builds:

```yaml
version: 0.2

cache:
  paths:
    - 'node_modules/**/*'
    - '/root/.pnpm-store/**/*'

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - pnpm audit
```

### Reports

Publish test and audit reports:

```yaml
version: 0.2

reports:
  audit-reports:
    files:
      - audit-report.json
    file-format: JSON

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - pnpm audit --output=json > audit-report.json
```

## Best Practices

### Security

1. **Use IAM roles** with least privilege:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "logs:CreateLogGroup",
           "logs:CreateLogStream",
           "logs:PutLogEvents"
         ],
         "Resource": "arn:aws:logs:*:*:*"
       }
     ]
   }
   ```

2. **Secure environment variables**:
   ```yaml
   env:
     variables:
       AUDIT_TOKEN: ***  # Use AWS Secrets Manager
   ```

3. **Use VPC configuration** for private resources:
   ```yaml
   vpc_config:
     vpc_id: vpc-12345678
     subnets:
       - subnet-12345678
     security_group_ids:
       - sg-12345678
   ```

### Performance

1. **Enable caching** for dependencies
2. **Use parallel builds** for multi-service projects
3. **Set appropriate timeouts** to prevent hanging
4. **Use build badges** for status monitoring

### Reliability

1. **Fail fast** on critical vulnerabilities
2. **Add retry logic** for transient failures
3. **Use health checks** for dependencies
4. **Monitor build performance**

## Troubleshooting

### Common Issues

#### 1. Log formatting not working

**Problem**: Log groups don't appear in CloudWatch.

**Solution**: Ensure you're using the correct output format:
```yaml
- pnpm audit --output=aws
```

#### 2. Build fails on warnings

**Problem**: Build fails even for non-critical vulnerabilities.

**Solution**: Use the `|| true` pattern:
```yaml
- pnpm audit --output=aws || true
```

#### 3. Slow build execution

**Problem**: Security audit takes too long.

**Solution**: Enable caching and optimize:
```yaml
cache:
  paths:
    - 'node_modules/**/*'
    - '/root/.pnpm-store/**/*'
```

#### 4. Memory issues

**Problem**: Build fails due to memory limits.

**Solution**: Increase build memory or optimize:
```yaml
phases:
  build:
    commands:
      - NODE_OPTIONS="--max-old-space-size=4096" pnpm audit
```

### Debugging

Enable debug logging:

```yaml
- pnpm audit --output=aws --debug
  env:
    DEBUG: pnpm-audit-hook:*
```

### Getting Help

If you encounter issues:

1. Check the [AWS CodeBuild documentation](https://docs.aws.amazon.com/codebuild/)
2. Review the [pnpm-audit-hook troubleshooting guide](./troubleshooting.md)
3. Search [existing issues](https://github.com/pnpm/pnpm-audit-hook/issues)
4. Open a new issue with detailed logs

## Example Workflows

### Complete Production Buildspec

```yaml
version: 0.2

env:
  variables:
    NODE_ENV: production
    AUDIT_SEVERITY: high

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  pre_build:
    commands:
      - echo "Running security audit..."
      - pnpm audit --output=aws --severity=$AUDIT_SEVERITY
  build:
    commands:
      - echo "Building application..."
      - pnpm run build
      - pnpm run test
  post_build:
    commands:
      - echo "Security audit completed"
      - if [ $? -ne 0 ]; then echo "Security audit failed"; exit 1; fi

artifacts:
  files:
    - 'dist/**/*'
    - 'audit-report.json'
  discard-paths: no
  name: production-build

cache:
  paths:
    - 'node_modules/**/*'
    - '/root/.pnpm-store/**/*'

reports:
  audit-reports:
    files:
      - audit-report.json
    file-format: JSON
```

### Multi-Service Buildspec

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - echo "Auditing frontend..."
      - pnpm --filter frontend audit --output=aws
      - echo "Auditing backend..."
      - pnpm --filter backend audit --output=aws
      - echo "Auditing shared..."
      - pnpm --filter shared audit --output=aws
      - echo "Building all services..."
      - pnpm run build
```

### CI/CD Pipeline with Deploy

```yaml
version: 0.2

env:
  variables:
    NODE_ENV: production

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  pre_build:
    commands:
      - echo "Running security audit..."
      - pnpm audit --output=aws
  build:
    commands:
      - echo "Building application..."
      - pnpm run build
  post_build:
    commands:
      - echo "Deploying to S3..."
      - aws s3 sync dist/ s3://my-bucket/ --delete

artifacts:
  files:
    - 'dist/**/*'
  discard-paths: yes
  name: production-artifact
```

## Integration with Other AWS Services

### AWS CodePipeline

```yaml
# pipeline.yml
version: 0.2
stages:
  - name: Source
    actions:
      - name: Source
        action_type_id:
          owner: AWS
          provider: S3
        configuration:
          S3Bucket: my-source-bucket
          S3ObjectKey: source.zip
        run_order: 1
  - name: Build
    actions:
      - name: Build
        action_type_id:
          owner: AWS
          provider: CodeBuild
        configuration:
          ProjectName: my-security-audit
        run_order: 1
```

### AWS Lambda

```yaml
# buildspec-lambda.yml
version: 0.2
phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - pnpm audit --output=json > audit-report.json
      - |
        aws lambda invoke \
          --function-name security-audit-processor \
          --payload file://audit-report.json \
          response.json
```

### AWS SNS

```yaml
# buildspec-sns.yml
version: 0.2
phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install -g pnpm
      - pnpm install --frozen-lockfile
  build:
    commands:
      - pnpm audit --output=aws
      - |
        if [ $? -ne 0 ]; then
          aws sns publish \
            --topic-arn arn:aws:sns:us-east-1:123456789012:security-alerts \
            --subject "Security Audit Failed" \
            --message "Security audit failed for build $CODEBUILD_BUILD_ID"
        fi
```

## Further Reading

- [AWS CodeBuild Documentation](https://docs.aws.amazon.com/codebuild/)
- [pnpm-audit-hook Configuration](../api/config.md)
- [Best Practices](./best-practices.md)
- [Troubleshooting Guide](./troubleshooting.md)

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team