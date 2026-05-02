/**
 * Centralized environment variable manager for pnpm-audit-hook.
 *
 * Provides type-safe access to all environment variables used throughout the
 * application, with validation, documentation, and backward compatibility.
 *
 * @module env-manager
 */

// =============================================================================
// Type Definitions
// =============================================================================

/**
 * All supported environment variables with their types and descriptions.
 * This serves as the single source of truth for env var documentation.
 */
export interface EnvVarDefinition {
  /** Whether the environment variable is required */
  required: boolean;
  /** Description of the environment variable */
  description: string;
  /** Valid values (for enum-like variables) */
  validValues?: readonly string[];
  /** Default value if not set */
  defaultValue?: string | boolean;
}

/**
 * Application-specific environment variables (pnpm-audit-*)
 */
export interface AppEnvVars {
  /** Suppress all non-error output */
  PNPM_AUDIT_QUIET: boolean;
  /** Enable debug logging */
  PNPM_AUDIT_DEBUG: boolean;
  /** Output results in JSON format */
  PNPM_AUDIT_JSON: boolean;
  /** Enable verbose output */
  PNPM_AUDIT_VERBOSE: boolean;
  /** Output format (human, json, azure, github, aws) */
  PNPM_AUDIT_FORMAT: string;
  /** Path to custom config file */
  PNPM_AUDIT_CONFIG_PATH: string;
  /** Comma-separated list of severities to block (e.g., "critical,high") */
  PNPM_AUDIT_BLOCK_SEVERITY: string;
  /** Block installation when all sources are disabled */
  PNPM_AUDIT_FAIL_ON_NO_SOURCES: boolean;
  /** Block installation when a source fails */
  PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: boolean;
  /** Skip API calls, use only static DB + cache */
  PNPM_AUDIT_OFFLINE: boolean;
}

/**
 * Registry environment variables
 */
export interface RegistryEnvVars {
  /** pnpm registry URL */
  PNPM_REGISTRY: string;
  /** npm config registry URL (lowercase) */
  npm_config_registry: string;
  /** npm config registry URL (uppercase) */
  NPM_CONFIG_REGISTRY: string;
}

/**
 * CI/CD environment variables
 */
export interface CIEnvVars {
  /** Generic CI environment flag */
  CI: boolean;
  /** Azure DevOps build flag */
  TF_BUILD: boolean;
  /** GitHub Actions flag */
  GITHUB_ACTIONS: boolean;
  /** GitLab CI flag */
  GITLAB_CI: boolean;
  /** Jenkins URL */
  JENKINS_URL: string;
  /** AWS CodeBuild build ID */
  CODEBUILD_BUILD_ID: string;
  /** GitHub Actions output file path */
  GITHUB_OUTPUT: string;
}

/**
 * Combined type for all environment variables
 */
export type AllEnvVars = AppEnvVars & RegistryEnvVars & CIEnvVars;

/**
 * Raw environment object type (as from process.env)
 */
export type RawEnv = Record<string, string | undefined>;

// =============================================================================
// Environment Variable Definitions (for documentation)
// =============================================================================

/**
 * All supported environment variables with their metadata.
 * Use this for documentation and validation purposes.
 */
export const ENV_VAR_DEFINITIONS: Record<string, EnvVarDefinition> = {
  // Application-specific variables
  PNPM_AUDIT_QUIET: {
    required: false,
    description: "Suppress all non-error output (quiet mode)",
    defaultValue: false,
  },
  PNPM_AUDIT_DEBUG: {
    required: false,
    description: "Enable debug logging output",
    defaultValue: false,
  },
  PNPM_AUDIT_JSON: {
    required: false,
    description: "Output results in JSON format",
    defaultValue: false,
  },
  PNPM_AUDIT_VERBOSE: {
    required: false,
    description: "Enable verbose output with additional details",
    defaultValue: false,
  },
  PNPM_AUDIT_FORMAT: {
    required: false,
    description: "Output format (human, json, azure, github, aws)",
    validValues: ["human", "json", "azure", "github", "aws"],
    defaultValue: "human",
  },
  PNPM_AUDIT_CONFIG_PATH: {
    required: false,
    description: "Path to custom config file (relative to project root)",
  },
  PNPM_AUDIT_BLOCK_SEVERITY: {
    required: false,
    description:
      'Comma-separated list of severities to block (e.g., "critical,high")',
    validValues: ["critical", "high", "medium", "low", "unknown"],
  },
  PNPM_AUDIT_FAIL_ON_NO_SOURCES: {
    required: false,
    description: "Block installation when all sources are disabled",
    defaultValue: true,
  },
  PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: {
    required: false,
    description: "Block installation when a source fails",
    defaultValue: true,
  },
  PNPM_AUDIT_OFFLINE: {
    required: false,
    description: "Skip API calls, use only static DB + cache",
    defaultValue: false,
  },

  // Registry variables
  PNPM_REGISTRY: {
    required: false,
    description: "pnpm registry URL",
  },
  npm_config_registry: {
    required: false,
    description: "npm config registry URL (lowercase)",
  },
  NPM_CONFIG_REGISTRY: {
    required: false,
    description: "npm config registry URL (uppercase)",
  },

  // CI/CD variables
  CI: {
    required: false,
    description: "Generic CI environment flag (set by most CI systems)",
    defaultValue: false,
  },
  TF_BUILD: {
    required: false,
    description: "Azure DevOps build flag (set to 'True' during builds)",
    defaultValue: false,
  },
  GITHUB_ACTIONS: {
    required: false,
    description: "GitHub Actions flag (set to 'true' during workflows)",
    defaultValue: false,
  },
  GITLAB_CI: {
    required: false,
    description: "GitLab CI flag (set to 'true' during pipelines)",
    defaultValue: false,
  },
  JENKINS_URL: {
    required: false,
    description: "Jenkins URL (set during Jenkins builds)",
  },
  CODEBUILD_BUILD_ID: {
    required: false,
    description: "AWS CodeBuild build ID (set during CodeBuild builds)",
  },
  GITHUB_OUTPUT: {
    required: false,
    description: "GitHub Actions output file path",
  },
};

// =============================================================================
// Validation Functions
// =============================================================================

/**
 * Parse a boolean environment variable.
 * Returns true only if the value is exactly "true" (case-insensitive).
 *
 * @param value - Raw environment variable value
 * @param defaultValue - Default value if not set
 * @returns Parsed boolean value
 */
function parseBoolean(
  value: string | undefined,
  defaultValue: boolean = false,
): boolean {
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === "true";
}

/**
 * Validate a string environment variable against allowed values.
 *
 * @param value - Raw environment variable value
 * @param validValues - Array of allowed values
 * @param defaultValue - Default value if not set or invalid
 * @returns Validated string value
 */
function validateString(
  value: string | undefined,
  validValues: readonly string[],
  defaultValue: string,
): string {
  if (value === undefined) return defaultValue;
  if (validValues.includes(value)) return value;
  return defaultValue;
}

/**
 * Get a string environment variable with validation.
 *
 * @param env - Raw environment object
 * @param key - Environment variable key
 * @param validValues - Optional array of allowed values
 * @param defaultValue - Default value if not set or invalid
 * @returns String value
 */
function getStringEnv(
  env: RawEnv,
  key: string,
  validValues?: readonly string[],
  defaultValue: string = "",
): string {
  const value = env[key];
  if (value === undefined) return defaultValue;
  if (validValues && !validValues.includes(value)) {
    return defaultValue;
  }
  return value;
}

/**
 * Get a boolean environment variable.
 *
 * @param env - Raw environment object
 * @param key - Environment variable key
 * @param defaultValue - Default value if not set
 * @returns Boolean value
 */
function getBooleanEnv(
  env: RawEnv,
  key: string,
  defaultValue: boolean = false,
): boolean {
  return parseBoolean(env[key], defaultValue);
}

// =============================================================================
// Main Environment Manager Functions
// =============================================================================

/**
 * Get all environment variables with proper parsing and validation.
 *
 * This function provides type-safe access to all environment variables,
 * with validation and backward compatibility.
 *
 * @param env - Raw environment object (defaults to process.env)
 * @returns Parsed and validated environment variables
 */
export function getEnvironmentVariables(
  env: RawEnv = process.env,
): AllEnvVars {
  return {
    // Application-specific variables
    PNPM_AUDIT_QUIET: getBooleanEnv(env, "PNPM_AUDIT_QUIET"),
    PNPM_AUDIT_DEBUG: getBooleanEnv(env, "PNPM_AUDIT_DEBUG"),
    PNPM_AUDIT_JSON: getBooleanEnv(env, "PNPM_AUDIT_JSON"),
    PNPM_AUDIT_VERBOSE: getBooleanEnv(env, "PNPM_AUDIT_VERBOSE"),
    PNPM_AUDIT_FORMAT: getStringEnv(
      env,
      "PNPM_AUDIT_FORMAT",
      ["human", "json", "azure", "github", "aws"],
      "human",
    ),
    PNPM_AUDIT_CONFIG_PATH: getStringEnv(env, "PNPM_AUDIT_CONFIG_PATH"),
    PNPM_AUDIT_BLOCK_SEVERITY: getStringEnv(env, "PNPM_AUDIT_BLOCK_SEVERITY"),
    PNPM_AUDIT_FAIL_ON_NO_SOURCES: getBooleanEnv(
      env,
      "PNPM_AUDIT_FAIL_ON_NO_SOURCES",
      true,
    ),
    PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: getBooleanEnv(
      env,
      "PNPM_AUDIT_FAIL_ON_SOURCE_ERROR",
      true,
    ),
    PNPM_AUDIT_OFFLINE: getBooleanEnv(env, "PNPM_AUDIT_OFFLINE"),

    // Registry variables
    PNPM_REGISTRY: getStringEnv(env, "PNPM_REGISTRY"),
    npm_config_registry: getStringEnv(env, "npm_config_registry"),
    NPM_CONFIG_REGISTRY: getStringEnv(env, "NPM_CONFIG_REGISTRY"),

    // CI/CD variables
    CI: getBooleanEnv(env, "CI"),
    TF_BUILD: getBooleanEnv(env, "TF_BUILD"),
    GITHUB_ACTIONS: getBooleanEnv(env, "GITHUB_ACTIONS"),
    GITLAB_CI: getBooleanEnv(env, "GITLAB_CI"),
    JENKINS_URL: getStringEnv(env, "JENKINS_URL"),
    CODEBUILD_BUILD_ID: getStringEnv(env, "CODEBUILD_BUILD_ID"),
    GITHUB_OUTPUT: getStringEnv(env, "GITHUB_OUTPUT"),
  };
}

/**
 * Check if running in a CI/CD environment.
 *
 * This function checks multiple CI/CD provider flags to determine if
 * the code is running in an automated environment.
 *
 * @param env - Raw environment object (defaults to process.env)
 * @returns true if running in CI, false otherwise
 */
export function isCIEnvironment(env: RawEnv = process.env): boolean {
  return (
    parseBoolean(env.CI) ||
    parseBoolean(env.TF_BUILD) ||
    parseBoolean(env.GITHUB_ACTIONS) ||
    parseBoolean(env.GITLAB_CI) ||
    env.JENKINS_URL !== undefined ||
    env.CODEBUILD_BUILD_ID !== undefined
  );
}

/**
 * Get the output format based on environment variables.
 *
 * This function determines the appropriate output format by checking
 * environment variables in order of priority:
 * 1. PNPM_AUDIT_JSON (explicit JSON mode)
 * 2. PNPM_AUDIT_FORMAT (explicit format selection)
 * 3. CI provider auto-detection (Azure, GitHub, AWS)
 *
 * @param env - Raw environment object (defaults to process.env)
 * @returns Output format string
 */
export function getOutputFormatFromEnv(
  env: RawEnv = process.env,
): string {
  // Explicit JSON mode takes highest priority
  if (parseBoolean(env.PNPM_AUDIT_JSON)) {
    return "json";
  }

  // Check explicit format setting
  const format = env.PNPM_AUDIT_FORMAT;
  if (format) {
    // Validate format
    const validFormats = ["human", "json", "azure", "github", "aws"];
    if (validFormats.includes(format)) {
      return format;
    }
  }

  // Auto-detect based on CI environment
  if (parseBoolean(env.TF_BUILD)) {
    return "azure";
  }

  if (parseBoolean(env.GITHUB_ACTIONS) && format !== "human") {
    return "github";
  }

  if (env.CODEBUILD_BUILD_ID) {
    return "aws";
  }

  return "human";
}

/**
 * Check if verbose mode is enabled.
 *
 * Verbose mode is enabled if:
 * - PNPM_AUDIT_VERBOSE=true, OR
 * - Running in any CI environment
 *
 * @param env - Raw environment object (defaults to process.env)
 * @returns true if verbose mode is enabled
 */
export function isVerboseMode(env: RawEnv = process.env): boolean {
  return parseBoolean(env.PNPM_AUDIT_VERBOSE) || isCIEnvironment(env);
}

/**
 * Get the registry URL from environment variables.
 *
 * Checks the following environment variables in order:
 * 1. PNPM_REGISTRY
 * 2. npm_config_registry
 * 3. NPM_CONFIG_REGISTRY
 *
 * @param env - Raw environment object (defaults to process.env)
 * @returns Registry URL or empty string if not set
 */
export function getRegistryUrlFromEnv(
  env: RawEnv = process.env,
): string {
  return (
    env.PNPM_REGISTRY || env.npm_config_registry || env.NPM_CONFIG_REGISTRY || ""
  );
}

/**
 * Validate environment variables and return any warnings.
 *
 * @param env - Raw environment object (defaults to process.env)
 * @returns Array of warning messages for invalid configuration
 */
export function validateEnvironmentVariables(
  env: RawEnv = process.env,
): string[] {
  const warnings: string[] = [];

  // Validate PNPM_AUDIT_FORMAT
  const format = env.PNPM_AUDIT_FORMAT;
  if (format) {
    const validFormats = ["human", "json", "azure", "github", "aws"];
    if (!validFormats.includes(format)) {
      warnings.push(
        `Invalid PNPM_AUDIT_FORMAT value: "${format}". Valid values: ${validFormats.join(", ")}`,
      );
    }
  }

  // Validate PNPM_AUDIT_BLOCK_SEVERITY
  const blockSeverity = env.PNPM_AUDIT_BLOCK_SEVERITY;
  if (blockSeverity) {
    const validSeverities = ["critical", "high", "medium", "low", "unknown"];
    const severities = blockSeverity.split(",").map((s) => s.trim());
    const invalid = severities.filter((s) => !validSeverities.includes(s));
    if (invalid.length > 0) {
      warnings.push(
        `Invalid PNPM_AUDIT_BLOCK_SEVERITY values: ${invalid.join(", ")}. Valid values: ${validSeverities.join(", ")}`,
      );
    }
  }

  // Validate boolean environment variables
  const booleanVars = [
    "PNPM_AUDIT_QUIET",
    "PNPM_AUDIT_DEBUG",
    "PNPM_AUDIT_JSON",
    "PNPM_AUDIT_VERBOSE",
    "PNPM_AUDIT_FAIL_ON_NO_SOURCES",
    "PNPM_AUDIT_FAIL_ON_SOURCE_ERROR",
    "PNPM_AUDIT_OFFLINE",
    "CI",
    "TF_BUILD",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
  ];

  for (const varName of booleanVars) {
    const value = env[varName];
    if (value !== undefined && value.toLowerCase() !== "true" && value.toLowerCase() !== "false") {
      warnings.push(
        `Invalid boolean value for ${varName}: "${value}". Expected "true" or "false".`,
      );
    }
  }

  return warnings;
}

/**
 * Get a summary of all environment variables for debugging.
 *
 * @param env - Raw environment object (defaults to process.env)
 * @returns Object with all env var values and their status
 */
export function getEnvironmentSummary(
  env: RawEnv = process.env,
): Record<string, { value: string | undefined; defined: boolean; description: string }> {
  const summary: Record<string, { value: string | undefined; defined: boolean; description: string }> = {};

  for (const [key, definition] of Object.entries(ENV_VAR_DEFINITIONS)) {
    summary[key] = {
      value: env[key],
      defined: env[key] !== undefined,
      description: definition.description,
    };
  }

  return summary;
}
