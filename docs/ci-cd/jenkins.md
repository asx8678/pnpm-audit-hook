# Jenkins Integration

Jenkins provides basic integration with pnpm-audit-hook, supporting standard exit codes and console output formatting.

## Quick Start

### Basic Pipeline

Create a `Jenkinsfile` in your project root:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
                sh 'pnpm audit'
            }
        }
    }
}
```

### Step-by-Step Setup

1. **Create Jenkinsfile**:
   ```bash
   touch Jenkinsfile
   ```

2. **Add the pipeline content** from the example above.

3. **Commit and push**:
   ```bash
   git add Jenkinsfile
   git commit -m "Add Jenkins security pipeline"
   git push
   ```

4. **Configure Jenkins job**:
   - Create a new Pipeline job
   - Point to your repository
   - Set the script path to `Jenkinsfile`
   - Run the build

## Features

### Console Output

pnpm-audit-hook outputs to Jenkins console:

```
[INFO] Source Status:
[INFO] GitHub Advisory: OK (1234ms)
[INFO] NVD: OK (2345ms)
[INFO] Vulnerability Details:
[ERROR] [CRITICAL] GHSA-xxxx-xxxx-xxxx in lodash@4.17.20
[WARNING] npm:lodash@4.17.20: Prototype Pollution in lodash
```

### Exit Codes

Jenkins uses exit codes to determine build status:

- **Exit code 0**: Build succeeded
- **Exit code 1**: Build failed (vulnerabilities found)
- **Exit code non-zero**: Build failed

### Build Status

Jenkins sets build status based on script execution:

```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'pnpm audit'
            }
        }
    }
    post {
        failure {
            echo 'Security audit failed'
        }
    }
}
```

## Advanced Configuration

### Custom Configuration

Create a `.pnpm-audit-hook.yml` file:

```yaml
# .pnpm-audit-hook.yml
output: human  # Jenkins doesn't have specific formatting
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

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
                sh 'pnpm audit'
            }
        }
        
        stage('Build') {
            steps {
                sh 'pnpm run build'
            }
        }
        
        stage('Test') {
            steps {
                sh 'pnpm test'
            }
        }
        
        stage('Deploy') {
            steps {
                sh './deploy.sh'
            }
        }
    }
}
```

### Environment Variables

Use environment variables for configuration:

```groovy
pipeline {
    agent any
    
    environment {
        NODE_ENV = 'production'
        AUDIT_SEVERITY = 'high'
    }
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
                sh 'pnpm audit --severity=$AUDIT_SEVERITY'
            }
        }
    }
}
```

### Artifacts

Archive audit reports:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
                sh 'pnpm audit --output=json > audit-report.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'audit-report.json', allowEmptyArchive: true
                }
            }
        }
    }
}
```

### Caching

Use Jenkins workspace caching:

```groovy
pipeline {
    agent any
    
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile --prefer-offline'
                sh 'pnpm audit'
            }
        }
    }
}
```

### Conditional Execution

Run audit only on specific branches:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            when {
                branch 'main'
            }
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
                sh 'pnpm audit'
            }
        }
    }
}
```

### Parallel Execution

Run audits in parallel:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            parallel {
                stage('Audit Frontend') {
                    steps {
                        sh 'pnpm --filter frontend audit'
                    }
                }
                stage('Audit Backend') {
                    steps {
                        sh 'pnpm --filter backend audit'
                    }
                }
                stage('Audit Shared') {
                    steps {
                        sh 'pnpm --filter shared audit'
                    }
                }
            }
        }
    }
}
```

### Notifications

Set up notifications for security issues:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'pnpm audit'
            }
            post {
                failure {
                    slackSend(
                        color: 'danger',
                        message: "Security audit failed for ${env.JOB_NAME} #${env.BUILD_NUMBER}"
                    )
                }
            }
        }
    }
}
```

## Best Practices

### Security

1. **Use credentials binding**:
   ```groovy
   pipeline {
       agent any
       stages {
           stage('Security Audit') {
               steps {
                   withCredentials([string(credentialsId: 'audit-token', variable: 'AUDIT_TOKEN')]) {
                       sh 'pnpm audit --token=$AUDIT_TOKEN'
                   }
               }
           }
       }
   }
   ```

2. **Limit pipeline permissions**:
   ```groovy
   pipeline {
       agent any
       options {
           buildDiscarder(logRotator(numToKeepStr: '10'))
       }
   }
   ```

3. **Use Jenkins credentials**:
   - Store sensitive data in Jenkins credentials
   - Use `withCredentials` to inject them

### Performance

1. **Enable workspace caching**
2. **Use parallel stages** for faster execution
3. **Set appropriate timeouts** to prevent hanging
4. **Use Docker agents** for isolation

### Reliability

1. **Fail fast** on critical vulnerabilities
2. **Use retry logic** for transient failures
3. **Add health checks** for dependencies
4. **Monitor pipeline performance**

## Troubleshooting

### Common Issues

#### 1. Build fails on warnings

**Problem**: Build fails even for non-critical vulnerabilities.

**Solution**: Use the `catchError` step:
```groovy
stage('Security Audit') {
    steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
            sh 'pnpm audit'
        }
    }
}
```

#### 2. Workspace issues

**Problem**: Workspace gets corrupted or has stale dependencies.

**Solution**: Clean workspace before running:
```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                cleanWs()
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
                sh 'pnpm audit'
            }
        }
    }
}
```

#### 3. Node.js version issues

**Problem**: Different Node.js versions cause issues.

**Solution**: Use nvm or nodejs plugin:
```groovy
pipeline {
    agent any
    tools {
        nodejs 'node-20'
    }
    stages {
        stage('Security Audit') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
                sh 'pnpm audit'
            }
        }
    }
}
```

#### 4. Memory issues

**Problem**: Build fails due to memory limits.

**Solution**: Increase JVM memory or optimize:
```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'NODE_OPTIONS="--max-old-space-size=4096" pnpm audit'
            }
        }
    }
}
```

### Debugging

Enable debug logging:

```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            environment {
                DEBUG = 'pnpm-audit-hook:*'
            }
            steps {
                sh 'pnpm audit --debug'
            }
        }
    }
}
```

### Getting Help

If you encounter issues:

1. Check the [Jenkins documentation](https://www.jenkins.io/doc/)
2. Review the [pnpm-audit-hook troubleshooting guide](./troubleshooting.md)
3. Search [existing issues](https://github.com/pnpm/pnpm-audit-hook/issues)
4. Open a new issue with detailed logs

## Example Workflows

### Complete Production Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        NODE_ENV = 'production'
        AUDIT_SEVERITY = 'high'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
            }
        }
        
        stage('Security Audit') {
            steps {
                sh 'pnpm audit --severity=$AUDIT_SEVERITY'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'audit-report.json', allowEmptyArchive: true
                }
                failure {
                    slackSend(
                        color: 'danger',
                        message: "Security audit failed for ${env.JOB_NAME} #${env.BUILD_NUMBER}"
                    )
                }
            }
        }
        
        stage('Build') {
            steps {
                sh 'pnpm run build'
            }
        }
        
        stage('Test') {
            steps {
                sh 'pnpm test'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh './deploy.sh'
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
    }
}
```

### Monorepo Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
            }
        }
        
        stage('Security Audit') {
            parallel {
                stage('Audit Frontend') {
                    steps {
                        sh 'pnpm --filter frontend audit'
                    }
                }
                stage('Audit Backend') {
                    steps {
                        sh 'pnpm --filter backend audit'
                    }
                }
                stage('Audit Shared') {
                    steps {
                        sh 'pnpm --filter shared audit'
                    }
                }
            }
        }
        
        stage('Build') {
            parallel {
                stage('Build Frontend') {
                    steps {
                        sh 'pnpm --filter frontend build'
                    }
                }
                stage('Build Backend') {
                    steps {
                        sh 'pnpm --filter backend build'
                    }
                }
            }
        }
        
        stage('Test') {
            steps {
                sh 'pnpm test'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh './deploy.sh'
            }
        }
    }
}
```

### Security Scanning Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
            }
        }
        
        stage('Security Audit') {
            steps {
                sh 'pnpm audit --output=json > audit-report.json'
                script {
                    def blocked = sh(script: 'jq \'.blocked\' audit-report.json', returnStdout: true).trim()
                    if (blocked == 'true') {
                        error 'Security audit failed - critical vulnerabilities found'
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'audit-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('Dependency Scan') {
            steps {
                sh 'pip install safety'
                sh 'safety check --json --output safety-report.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'safety-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('Build') {
            steps {
                sh 'pnpm run build'
            }
        }
    }
}
```

## Integration with Jenkins Plugins

### Slack Notifications

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'pnpm audit'
            }
            post {
                failure {
                    slackSend(
                        color: 'danger',
                        message: "Security audit failed for ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        channel: '#security-alerts'
                    )
                }
            }
        }
    }
}
```

### Email Notifications

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'pnpm audit'
            }
            post {
                failure {
                    emailext(
                        subject: "Security Audit Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: "Security audit failed. Please check the build logs.",
                        to: 'security-team@company.com'
                    )
                }
            }
        }
    }
}
```

### SonarQube Integration

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh 'pnpm audit'
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'pnpm run sonar'
                }
            }
        }
    }
}
```

## Further Reading

- [Jenkins Documentation](https://www.jenkins.io/doc/)
- [pnpm-audit-hook Configuration](../api/config.md)
- [Best Practices](./best-practices.md)
- [Troubleshooting Guide](./troubleshooting.md)

---

**Last updated**: December 2024  
**Maintainer**: pnpm-audit-hook team