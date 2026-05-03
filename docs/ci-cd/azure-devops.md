# Azure DevOps Integration

Azure DevOps provides excellent integration with pnpm-audit-hook, offering full support for annotations, log grouping, and pipeline variables.

## Quick Start

### Basic Pipeline

Create an `azure-pipelines.yml` file in your project root:

```yaml
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20.x'
    displayName: 'Install Node.js'

  - script: |
      npm install -g pnpm
      pnpm install --frozen-lockfile
    displayName: 'Install Dependencies'

  - script: pnpm audit
    displayName: 'Security Audit'
```

### Step-by-Step Setup

1. **Create pipeline file**:
   ```bash
   touch azure-pipelines.yml
   ```

2. **Add the pipeline content** from the example above.

3. **Commit and push**:
   ```bash
   git add azure-pipelines.yml
   git commit -m "Add Azure DevOps security pipeline"
   git push
   ```

4. **Create pipeline in Azure DevOps**:
   - Go to your project in Azure DevOps
   - Navigate to **Pipelines** > **New pipeline**
   - Select your repository
   - Choose **Existing Azure Pipelines YAML file**
   - Select `azure-pipelines.yml`
   - Run the pipeline

## Features

### Annotations

pnpm-audit-hook creates Azure DevOps annotations using logging commands:

```
##[warning]npm:lodash@4.17.20: Prototype Pollution in lodash
##[error][CRITICAL] GHSA-xxxx-xxxx-xxxx in lodash@4.17.20
```

These annotations appear in the pipeline summary and build logs.

### Log Groups

The tool uses Azure DevOps log grouping:

```
##[group]Source Status
GitHub Advisory: OK (1234ms)
NVD: OK (2345ms)
##[endgroup]

##[group]Vulnerability Details
##[error][CRITICAL] GHSA-xxxx-xxxx-xxxx in lodash@4.17.20
##[endgroup]
```

### Pipeline Variables

Set pipeline variables for conditional logic:

```yaml
- script: pnpm audit --output=azure
  displayName: 'Security Audit'

- script: |
    if [ "$(AUDIT_BLOCKED)" == "true" ]; then
      echo "##vso[task.logissue type=error]Security audit failed"
      exit 1
    fi
  displayName: 'Check Audit Results'
```

## Advanced Configuration

### Custom Configuration

Create a `.pnpm-audit-hook.yml` file:

```yaml
# .pnpm-audit-hook.yml
output: azure
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
trigger:
  - main
  - develop

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: '20.x'
            displayName: 'Install Node.js'
          - script: |
              npm install -g pnpm
              pnpm install --frozen-lockfile
            displayName: 'Install Dependencies'
          - script: pnpm run build
            displayName: 'Build'

  - stage: SecurityAudit
    dependsOn: Build
    jobs:
      - job: AuditJob
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: '20.x'
            displayName: 'Install Node.js'
          - script: |
              npm install -g pnpm
              pnpm install --frozen-lockfile
            displayName: 'Install Dependencies'
          - script: pnpm audit --output=azure
            displayName: 'Security Audit'
```

### Caching

Enable caching for faster pipeline execution:

```yaml
steps:
  - task: Cache@2
    inputs:
      key: 'pnpm | "lock.json"'
      restoreKeys: |
        pnpm
      path: ~/.pnpm-store
    displayName: 'Cache pnpm store'

  - script: |
      npm install -g pnpm
      pnpm install --frozen-lockfile
    displayName: 'Install Dependencies'
```

### Conditional Execution

Run audit only on specific branches:

```yaml
trigger:
  - main

steps:
  - script: pnpm audit --output=azure
    displayName: 'Security Audit'
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
```

### Artifacts and Reporting

Generate and publish audit reports:

```yaml
steps:
  - script: pnpm audit --output=json > $(Build.ArtifactStagingDirectory)/audit-report.json
    displayName: 'Generate Audit Report'
    continueOnError: true

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)'
      ArtifactName: 'audit-report'
      publishLocation: 'Container'
    displayName: 'Publish Audit Report'
    condition: always()
```

### Notifications

Set up notifications for security issues:

```yaml
steps:
  - script: pnpm audit --output=azure
    displayName: 'Security Audit'
    
  - task: AzureCLI@2
    displayName: 'Send Alert'
    condition: failed()
    inputs:
      azureSubscription: 'your-service-connection'
      scriptType: 'bash'
      scriptLocation: 'inlineScript'
      inlineScript: |
        az devops notification mail send \
          --address "security-team@company.com" \
          --subject "Security Audit Failed" \
          --message "Security audit failed for build $(Build.BuildNumber)"
```

## Best Practices

### Security

1. **Use service connections** for Azure resources:
   ```yaml
   - task: AzureCLI@2
     inputs:
       azureSubscription: 'your-service-connection'
   ```

2. **Secure variables** for sensitive configuration:
   ```yaml
   variables:
     - name: audit-token
       value: $(AUDIT_TOKEN)
       secret: true
   ```

3. **Limit pipeline permissions**:
   ```yaml
   resources:
     repositories:
       - repository: self
         type: git
         ref: refs/heads/main
   ```

### Performance

1. **Enable caching** for dependencies
2. **Use parallel jobs** for faster execution
3. **Set appropriate timeouts** to prevent hanging
4. **Use matrix strategies** for multi-platform testing

### Reliability

1. **Fail fast** on critical vulnerabilities
2. **Use retry logic** for transient failures
3. **Add health checks** for dependencies
4. **Monitor pipeline performance**

## Troubleshooting

### Common Issues

#### 1. Annotations not appearing

**Problem**: Vulnerability annotations don't show up in the pipeline summary.

**Solution**: Ensure you're using the correct output format:
```yaml
- script: pnpm audit --output=azure
```

#### 2. Pipeline fails on warnings

**Problem**: Pipeline fails even for non-critical vulnerabilities.

**Solution**: Use the `continueOnError` option:
```yaml
- script: pnpm audit --output=azure
  displayName: 'Security Audit'
  continueOnError: true
```

#### 3. Variables not set

**Problem**: Pipeline variables aren't being set by the audit.

**Solution**: Check the variable names and use the correct syntax:
```yaml
- script: |
    pnpm audit --output=azure
    echo "AUDIT_BLOCKED=$(AUDIT_BLOCKED)"
```

#### 4. Slow pipeline execution

**Problem**: Security audit takes too long.

**Solution**: Enable caching and optimize:
```yaml
- task: Cache@2
  inputs:
    key: 'pnpm | "lock.json"'
    restoreKeys: |
      pnpm
    path: ~/.pnpm-store
```

### Debugging

Enable debug logging:

```yaml
- script: pnpm audit --output=azure --debug
  displayName: 'Security Audit'
  env:
    DEBUG: pnpm-audit-hook:*
```

### Getting Help

If you encounter issues:

1. Check the [Azure DevOps documentation](https://docs.microsoft.com/en-us/azure/devops/pipelines/)
2. Review the [pnpm-audit-hook troubleshooting guide](./troubleshooting.md)
3. Search [existing issues](https://github.com/pnpm/pnpm-audit-hook/issues)
4. Open a new issue with detailed logs

## Example Workflows

### Complete Production Pipeline

```yaml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - package.json
      - pnpm-lock.yaml

pr:
  branches:
    include:
      - main

variables:
  - name: node-version
    value: '20'

stages:
  - stage: SecurityAudit
    displayName: 'Security Audit'
    jobs:
      - job: Audit
        displayName: 'Run Security Audit'
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: $(node-version)
            displayName: 'Install Node.js'

          - task: Cache@2
            inputs:
              key: 'pnpm | "lock.json"'
              restoreKeys: |
                pnpm
              path: ~/.pnpm-store
            displayName: 'Cache pnpm store'

          - script: |
              npm install -g pnpm
              pnpm install --frozen-lockfile
            displayName: 'Install Dependencies'

          - script: pnpm audit --output=azure
            displayName: 'Run Security Audit'
            name: audit

          - script: |
              if [ "$(audit.AUDIT_BLOCKED)" == "true" ]; then
                echo "##vso[task.logissue type=error]Security audit failed - critical vulnerabilities found"
                exit 1
              fi
            displayName: 'Check Audit Results'

          - task: PublishBuildArtifacts@1
            inputs:
              PathtoPublish: '$(Build.SourcesDirectory)'
              ArtifactName: 'audit-report'
              publishLocation: 'Container'
            displayName: 'Publish Audit Report'
            condition: always()

  - stage: Deploy
    dependsOn: SecurityAudit
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    displayName: 'Deploy'
    jobs:
      - deployment: DeployProduction
        displayName: 'Deploy to Production'
        pool:
          vmImage: 'ubuntu-latest'
        environment: 'production'
        strategy:
          runOnce:
            deploy:
              steps:
                - script: ./deploy.sh
                  displayName: 'Deploy Application'
```

### Monorepo Pipeline

```yaml
trigger:
  - main
  - develop

variables:
  - name: node-version
    value: '20'

stages:
  - stage: Build
    displayName: 'Build'
    jobs:
      - job: BuildPackages
        displayName: 'Build Packages'
        pool:
          vmImage: 'ubuntu-latest'
        strategy:
          matrix:
            frontend:
              package: 'frontend'
            backend:
              package: 'backend'
            shared:
              package: 'shared'
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: $(node-version)
            displayName: 'Install Node.js'

          - script: |
              npm install -g pnpm
              pnpm install --frozen-lockfile
            displayName: 'Install Dependencies'

          - script: pnpm --filter $(package) build
            displayName: 'Build $(package)'

  - stage: SecurityAudit
    dependsOn: Build
    displayName: 'Security Audit'
    jobs:
      - job: AuditPackages
        displayName: 'Audit Packages'
        pool:
          vmImage: 'ubuntu-latest'
        strategy:
          matrix:
            frontend:
              package: 'frontend'
            backend:
              package: 'backend'
            shared:
              package: 'shared'
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: $(node-version)
            displayName: 'Install Node.js'

          - script: |
              npm install -g pnpm
              pnpm install --frozen-lockfile
            displayName: 'Install Dependencies'

          - script: pnpm --filter $(package) audit --output=azure
            displayName: 'Audit $(package)'
```

## Further Reading

- [Azure DevOps Documentation](https://docs.microsoft.com/en-us/azure/devops/pipelines/)
- [pnpm-audit-hook Configuration](../api/config.md)
- [Best Practices](./best-practices.md)
- [Troubleshooting Guide](./troubleshooting.md)

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team