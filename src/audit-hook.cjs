"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_POLICY_FILE = "pnpm-audit-policy.json";
const DEFAULT_POLICY = Object.freeze({
  onViolation: "fail",
  onError: "fail",
  rules: [],
});
const VALID_BEHAVIORS = new Set(["fail", "warn"]);

function createAuditHooks(options = {}) {
  const fsApi = options.fs || fs;
  const env = options.env || process.env;
  const cwd = options.cwd || process.cwd();
  const policyPath = resolvePolicyPath(env.PNPM_AUDIT_POLICY_PATH, cwd);
  let cachedPolicy;

  return {
    readPackage(packageJson, context = {}) {
      const log =
        context && typeof context.log === "function"
          ? context.log.bind(context)
          : () => {};

      if (!cachedPolicy) {
        cachedPolicy = loadPolicy({ fsApi, env, policyPath, log });
      }

      const violation = findViolation(packageJson, cachedPolicy.rules);
      if (!violation) {
        return packageJson;
      }

      const message = formatViolationMessage(packageJson, violation);
      if (cachedPolicy.onViolation === "warn") {
        log(message);
        return packageJson;
      }

      throw new Error(message);
    },
  };
}

function loadPolicy({ fsApi, env, policyPath, log }) {
  const bootstrapOnError = parseBehavior(
    env.PNPM_AUDIT_ON_ERROR,
    "PNPM_AUDIT_ON_ERROR",
    DEFAULT_POLICY.onError
  );

  let rawPolicy;
  try {
    rawPolicy = readPolicyFile(fsApi, policyPath);
  } catch (error) {
    if (bootstrapOnError === "warn") {
      logWarning(log, error.message);
      return createFallbackPolicy(env, bootstrapOnError);
    }
    throw error;
  }

  const onError = parseBehavior(
    env.PNPM_AUDIT_ON_ERROR ?? rawPolicy.onError,
    env.PNPM_AUDIT_ON_ERROR == null ? "onError" : "PNPM_AUDIT_ON_ERROR",
    DEFAULT_POLICY.onError
  );

  try {
    const onViolation = parseBehavior(
      env.PNPM_AUDIT_ON_VIOLATION ?? rawPolicy.onViolation,
      env.PNPM_AUDIT_ON_VIOLATION == null
        ? "onViolation"
        : "PNPM_AUDIT_ON_VIOLATION",
      DEFAULT_POLICY.onViolation
    );
    const rules = normalizeRules(rawPolicy.rules, policyPath);

    return {
      onViolation,
      onError,
      rules,
    };
  } catch (error) {
    if (onError === "warn") {
      logWarning(log, error.message);
      return createFallbackPolicy(env, onError);
    }
    throw error;
  }
}

function createFallbackPolicy(env, onError) {
  return {
    onViolation: parseBehavior(
      env.PNPM_AUDIT_ON_VIOLATION,
      "PNPM_AUDIT_ON_VIOLATION",
      DEFAULT_POLICY.onViolation
    ),
    onError,
    rules: [],
  };
}

function readPolicyFile(fsApi, policyPath) {
  if (typeof fsApi.existsSync === "function" && !fsApi.existsSync(policyPath)) {
    return {};
  }

  let raw;
  try {
    raw = fsApi.readFileSync(policyPath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return {};
    }
    throw new Error(
      `[pnpm-audit-hook] Could not read policy file ${policyPath}: ${error.message}`
    );
  }

  if (raw.trim() === "") {
    return {};
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `[pnpm-audit-hook] Invalid JSON in policy file ${policyPath}: ${error.message}`
    );
  }

  if (!isPlainObject(parsed)) {
    throw new Error(
      `[pnpm-audit-hook] Policy file ${policyPath} must contain a JSON object.`
    );
  }

  return parsed;
}

function normalizeRules(rules, policyPath) {
  if (rules == null) {
    return [];
  }

  if (!Array.isArray(rules)) {
    throw new Error(
      `[pnpm-audit-hook] Invalid "rules" in ${policyPath}: expected an array.`
    );
  }

  return rules.map((rule, ruleIndex) => normalizeRule(rule, ruleIndex, policyPath));
}

function normalizeRule(rule, ruleIndex, policyPath) {
  const ruleLabel = `rules[${ruleIndex}]`;
  if (!isPlainObject(rule)) {
    throw new Error(
      `[pnpm-audit-hook] ${ruleLabel} in ${policyPath} must be an object.`
    );
  }

  const name = normalizeString(rule.name, `${ruleLabel}.name`, policyPath);
  let versions;
  if (rule.versions != null) {
    if (!Array.isArray(rule.versions) || rule.versions.length === 0) {
      throw new Error(
        `[pnpm-audit-hook] ${ruleLabel}.versions in ${policyPath} must be a non-empty array when provided.`
      );
    }
    versions = rule.versions.map((version, versionIndex) =>
      normalizeString(
        version,
        `${ruleLabel}.versions[${versionIndex}]`,
        policyPath
      )
    );
  }

  let reason;
  if (rule.reason != null) {
    reason = normalizeString(rule.reason, `${ruleLabel}.reason`, policyPath);
  }

  return { name, versions, reason };
}

function normalizeString(value, label, policyPath) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(
      `[pnpm-audit-hook] ${label} in ${policyPath} must be a non-empty string.`
    );
  }

  return value.trim();
}

function parseBehavior(value, label, fallback) {
  const resolved =
    value == null ? fallback : String(value).trim().toLowerCase();

  if (!VALID_BEHAVIORS.has(resolved)) {
    throw new Error(
      `[pnpm-audit-hook] Invalid ${label} value "${value}". Expected "fail" or "warn".`
    );
  }

  return resolved;
}

function findViolation(packageJson, rules) {
  if (!isPlainObject(packageJson) || !packageJson.name) {
    return null;
  }

  for (const rule of rules) {
    if (rule.name !== packageJson.name) {
      continue;
    }
    if (!rule.versions) {
      return rule;
    }
    if (rule.versions.some((versionMatcher) => versionMatches(packageJson.version, versionMatcher))) {
      return rule;
    }
  }

  return null;
}

function versionMatches(version, matcher) {
  if (matcher === "*") {
    return true;
  }

  if (typeof version !== "string" || version.length === 0) {
    return false;
  }

  if (matcher === version) {
    return true;
  }

  if (matcher.endsWith(".*")) {
    const prefix = matcher.slice(0, -1);
    return version.startsWith(prefix);
  }

  return false;
}

function formatViolationMessage(packageJson, violation) {
  const packageName = packageJson.name || "<unknown>";
  const packageVersion = packageJson.version || "<unknown>";
  const matcherSegment = violation.versions
    ? ` (matched rules: ${violation.versions.join(", ")})`
    : "";
  const reasonSegment = violation.reason ? ` Reason: ${violation.reason}` : "";

  return `[pnpm-audit-hook] Blocked package ${packageName}@${packageVersion}${matcherSegment}.${reasonSegment}`;
}

function resolvePolicyPath(policyPathFromEnv, cwd) {
  if (!policyPathFromEnv) {
    return path.join(cwd, DEFAULT_POLICY_FILE);
  }
  return path.isAbsolute(policyPathFromEnv)
    ? policyPathFromEnv
    : path.join(cwd, policyPathFromEnv);
}

function logWarning(log, message) {
  log(`[pnpm-audit-hook] ${message} Continuing because onError=warn.`);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

module.exports = {
  createAuditHooks,
  _internal: {
    findViolation,
    formatViolationMessage,
    normalizeRules,
    parseBehavior,
    readPolicyFile,
    resolvePolicyPath,
    versionMatches,
  },
};
