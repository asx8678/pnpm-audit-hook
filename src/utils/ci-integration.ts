/**
 * CI/CD integration utilities for pnpm-audit-hook.
 * 
 * Provides platform-specific integration for GitHub Actions, Azure DevOps,
 * and AWS CodeBuild with annotations and log formatting.
 * 
 * @module ci-integration
 */

import type { CIPlatform, CIAnnotation, CIIntegration, LogLevel } from './logger-types';

// =============================================================================
// CI Platform Detection
// =============================================================================

/**
 * Detect CI platform from environment variables
 */
export function detectCIPlatform(): CIPlatform {
  // GitHub Actions
  if (process.env.GITHUB_ACTIONS === 'true') {
    return {
      name: 'github-actions',
      isCI: true,
      envVars: {
        GITHUB_ACTIONS: process.env.GITHUB_ACTIONS,
        GITHUB_OUTPUT: process.env.GITHUB_OUTPUT,
        GITHUB_WORKFLOW: process.env.GITHUB_WORKFLOW,
        GITHUB_RUN_ID: process.env.GITHUB_RUN_ID,
        GITHUB_SHA: process.env.GITHUB_SHA,
      },
    };
  }

  // Azure DevOps
  if (process.env.TF_BUILD === 'True') {
    return {
      name: 'azure-devops',
      isCI: true,
      envVars: {
        TF_BUILD: process.env.TF_BUILD,
        BUILD_BUILDID: process.env.BUILD_BUILDID,
        BUILD_BUILDNUMBER: process.env.BUILD_BUILDNUMBER,
        SYSTEM_TEAMPROJECT: process.env.SYSTEM_TEAMPROJECT,
      },
    };
  }

  // GitLab CI
  if (process.env.GITLAB_CI === 'true') {
    return {
      name: 'gitlab-ci',
      isCI: true,
      envVars: {
        GITLAB_CI: process.env.GITLAB_CI,
        CI_PIPELINE_ID: process.env.CI_PIPELINE_ID,
        CI_COMMIT_SHA: process.env.CI_COMMIT_SHA,
      },
    };
  }

  // Jenkins
  if (process.env.JENKINS_URL) {
    return {
      name: 'jenkins',
      isCI: true,
      envVars: {
        JENKINS_URL: process.env.JENKINS_URL,
        BUILD_NUMBER: process.env.BUILD_NUMBER,
        JOB_NAME: process.env.JOB_NAME,
      },
    };
  }

  // AWS CodeBuild
  if (process.env.CODEBUILD_BUILD_ID) {
    return {
      name: 'aws-codebuild',
      isCI: true,
      envVars: {
        CODEBUILD_BUILD_ID: process.env.CODEBUILD_BUILD_ID,
        CODEBUILD_BUILD_SUMMARY: process.env.CODEBUILD_BUILD_SUMMARY,
      },
    };
  }

  // Generic CI detection
  if (process.env.CI === 'true') {
    return {
      name: 'generic-ci',
      isCI: true,
      envVars: {
        CI: process.env.CI,
      },
    };
  }

  return {
    name: 'local',
    isCI: false,
    envVars: {},
  };
}

// =============================================================================
// GitHub Actions Integration
// =============================================================================

/**
 * GitHub Actions CI integration
 */
export class GitHubActionsIntegration implements CIIntegration {
  detect(): CIPlatform {
    return detectCIPlatform();
  }

  emitAnnotation(annotation: CIAnnotation): void {
    const { type, message, file, line, column } = annotation;
    
    // GitHub Actions annotation format
    // See: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-a-warning-message
    const parts: string[] = [];
    
    if (file) {
      parts.push(`file=${file}`);
    }
    if (line) {
      parts.push(`line=${line}`);
    }
    if (column) {
      parts.push(`col=${column}`);
    }
    
    const properties = parts.length > 0 ? ` ${parts.join(',')}` : '';
    
    switch (type) {
      case 'warning':
        console.log(`::warning${properties}::${message}`);
        break;
      case 'error':
        console.log(`::error${properties}::${message}`);
        break;
      case 'notice':
        console.log(`::notice${properties}::${message}`);
        break;
    }
  }

  emitLog(message: string, level: LogLevel = 'info'): void {
    // GitHub Actions doesn't have special log formatting
    // Just output normally
    switch (level) {
      case 'error':
        console.error(message);
        break;
      case 'warn':
        console.warn(message);
        break;
      default:
        console.log(message);
    }
  }

  setOutput(name: string, value: string): void {
    const githubOutput = process.env.GITHUB_OUTPUT;
    if (!githubOutput) return;
    
    const fs = require('fs');
    fs.appendFileSync(githubOutput, `${name}=${value}\n`);
  }
}

// =============================================================================
// Azure DevOps Integration
// =============================================================================

/**
 * Azure DevOps CI integration
 */
export class AzureDevOpsIntegration implements CIIntegration {
  detect(): CIPlatform {
    return detectCIPlatform();
  }

  emitAnnotation(annotation: CIAnnotation): void {
    const { type, message, file, line } = annotation;
    
    // Azure DevOps logging commands
    // See: https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands
    const logType = type === 'error' ? 'error' : type === 'warning' ? 'warning' : 'notice';
    
    let command = `##vso[task.logissue type=${logType}`;
    if (file) command += `;sourcepath=${file}`;
    if (line) command += `;linenumber=${line}`;
    command += `]${message}`;
    
    console.log(command);
  }

  emitLog(message: string, level: LogLevel = 'info'): void {
    switch (level) {
      case 'error':
        console.error(`##vso[task.logissue type=error]${message}`);
        break;
      case 'warn':
        console.warn(`##vso[task.logissue type=warning]${message}`);
        break;
      default:
        console.log(message);
    }
  }

  setOutput(name: string, value: string): void {
    console.log(`##vso[task.setvariable variable=${name}]${value}`);
  }
}

// =============================================================================
// AWS CodeBuild Integration
// =============================================================================

/**
 * AWS CodeBuild CI integration
 */
export class AWSCodeBuildIntegration implements CIIntegration {
  detect(): CIPlatform {
    return detectCIPlatform();
  }

  emitAnnotation(annotation: CIAnnotation): void {
    const { type, message, file, line } = annotation;
    
    // AWS CodeBuild uses CloudWatch Logs formatting
    // See: https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
    const logType = type === 'error' ? 'ERROR' : type === 'warning' ? 'WARN' : 'INFO';
    
    let logMessage = `[${logType}] ${message}`;
    if (file && line) {
      logMessage += ` (${file}:${line})`;
    }
    
    console.log(logMessage);
  }

  emitLog(message: string, level: LogLevel = 'info'): void {
    switch (level) {
      case 'error':
        console.error(`[ERROR] ${message}`);
        break;
      case 'warn':
        console.warn(`[WARN] ${message}`);
        break;
      default:
        console.log(`[INFO] ${message}`);
    }
  }

  setOutput(name: string, value: string): void {
    // AWS CodeBuild doesn't have a direct output mechanism
    // Log it for now
    console.log(`[OUTPUT] ${name}=${value}`);
  }
}

// =============================================================================
// Generic CI Integration
// =============================================================================

/**
 * Generic CI integration for unsupported platforms
 */
export class GenericCIIntegration implements CIIntegration {
  detect(): CIPlatform {
    return detectCIPlatform();
  }

  emitAnnotation(annotation: CIAnnotation): void {
    const { type, message } = annotation;
    const prefix = type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️';
    console.log(`${prefix} ${message}`);
  }

  emitLog(message: string, level: LogLevel = 'info'): void {
    switch (level) {
      case 'error':
        console.error(message);
        break;
      case 'warn':
        console.warn(message);
        break;
      default:
        console.log(message);
    }
  }

  setOutput(name: string, value: string): void {
    console.log(`[OUTPUT] ${name}=${value}`);
  }
}

// =============================================================================
// Factory and Singleton
// =============================================================================

/**
 * Create CI integration based on detected platform
 */
export function createCIIntegration(): CIIntegration {
  const platform = detectCIPlatform();
  
  switch (platform.name) {
    case 'github-actions':
      return new GitHubActionsIntegration();
    case 'azure-devops':
      return new AzureDevOpsIntegration();
    case 'aws-codebuild':
      return new AWSCodeBuildIntegration();
    default:
      return new GenericCIIntegration();
  }
}

/**
 * Singleton CI integration instance
 */
let ciIntegrationInstance: CIIntegration | null = null;

/**
 * Get or create CI integration singleton
 */
export function getCIIntegration(): CIIntegration {
  if (!ciIntegrationInstance) {
    ciIntegrationInstance = createCIIntegration();
  }
  return ciIntegrationInstance;
}

// =============================================================================
// Convenience Functions
// =============================================================================

/**
 * Emit warning annotation to CI system
 */
export function emitWarning(message: string, file?: string, line?: number): void {
  getCIIntegration().emitAnnotation({
    type: 'warning',
    message,
    file,
    line,
  });
}

/**
 * Emit error annotation to CI system
 */
export function emitError(message: string, file?: string, line?: number): void {
  getCIIntegration().emitAnnotation({
    type: 'error',
    message,
    file,
    line,
  });
}

/**
 * Emit notice annotation to CI system
 */
export function emitNotice(message: string, file?: string, line?: number): void {
  getCIIntegration().emitAnnotation({
    type: 'notice',
    message,
    file,
    line,
  });
}

/**
 * Set output variable in CI system
 */
export function setCIOutput(name: string, value: string): void {
  getCIIntegration().setOutput(name, value);
}

/**
 * Check if running in CI environment
 */
export function isCI(): boolean {
  return detectCIPlatform().isCI;
}

/**
 * Get current CI platform name
 */
export function getCIPlatformName(): string {
  return detectCIPlatform().name;
}