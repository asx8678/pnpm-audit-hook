/**
 * CVSS Vector Validator
 *
 * Provides validation and parsing for CVSS v2.0, v3.0, v3.1, and v4.0 vectors.
 * Validates vector format, required metrics, and calculates scores.
 *
 * @module utils/cvss-validator
 *
 * @see {@link https://www.first.org/cvss/} - CVSS specification
 * @see {@link https://www.first.org/cvss/v3.1/specification-document} - CVSS v3.1 spec
 * @see {@link https://www.first.org/cvss/v4.0/specification-document} - CVSS v4.0 spec
 */

import type { Severity } from "../types";
import { scoreToSeverity } from "./cvss";

// ─────────────────────────────────────────────────────
// §1  Types
// ─────────────────────────────────────────────────────

/** CVSS vector version */
export type CvssVersion = "2.0" | "3.0" | "3.1" | "4.0";

/**
 * Parsed CVSS vector information with full metrics and validation status.
 */
export interface CvssVectorInfo {
  /** CVSS version */
  version: CvssVersion;
  /** Numeric score (0.0 - 10.0) */
  score: number;
  /** Severity level derived from score */
  severity: Severity;
  /** Original vector string */
  vector: string;
  /** Parsed metrics as key-value pairs */
  metrics: Record<string, string>;
  /** Whether the vector is valid */
  isValid: boolean;
  /** Validation error messages (only present if invalid) */
  validationErrors?: string[];
}

/**
 * Result of CVSS vector validation.
 */
export interface CvssValidationResult {
  /** Whether the vector is valid */
  isValid: boolean;
  /** Detected CVSS version (if version prefix found) */
  version?: CvssVersion;
  /** Calculated score (if valid) */
  score?: number;
  /** Severity level (if valid) */
  severity?: Severity;
  /** Parsed metrics (if version detected) */
  metrics?: Record<string, string>;
  /** List of validation error messages */
  errors: string[];
}

/**
 * CVSS v2 metric values.
 */
interface CvssV2Metrics {
  AV: "N" | "A" | "L" | "P";
  AC: "H" | "M" | "L";
  Au: "N" | "S" | "R";
  C: "N" | "P" | "C";
  I: "N" | "P" | "C";
  A: "N" | "P" | "C";
}

/**
 * CVSS v3.x metric values.
 */
interface CvssV3Metrics {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  PR: "N" | "L" | "H";
  UI: "N" | "R";
  S: "U" | "C";
  C: "H" | "L" | "N";
  I: "H" | "L" | "N";
  A: "H" | "L" | "N";
}

/**
 * CVSS v4.0 metric values (extended set).
 */
interface CvssV4Metrics {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  AT: "N" | "P";
  PR: "N" | "L" | "H";
  UI: "N" | "A" | "P";
  VC: "H" | "L" | "N";
  VI: "H" | "L" | "N";
  VA: "H" | "L" | "N";
  SC: "H" | "L" | "N";
  SI: "H" | "L" | "N";
  SA: "H" | "L" | "N";
}

// ─────────────────────────────────────────────────────
// §2  Metric Definitions
// ─────────────────────────────────────────────────────

/** Required metrics for CVSS v2.0 */
const CVSS_V2_REQUIRED_METRICS: readonly string[] = [
  "AV", "AC", "Au", "C", "I", "A",
];

/** Required metrics for CVSS v3.0/v3.1 */
const CVSS_V3_REQUIRED_METRICS: readonly string[] = [
  "AV", "AC", "PR", "UI", "S", "C", "I", "A",
];

/** Required metrics for CVSS v4.0 */
const CVSS_V4_REQUIRED_METRICS: readonly string[] = [
  "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

/** Valid metric values for CVSS v2.0 */
const CVSS_V2_VALID_VALUES: Record<string, readonly string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["H", "M", "L"],
  Au: ["N", "S", "R"],
  C: ["N", "P", "C"],
  I: ["N", "P", "C"],
  A: ["N", "P", "C"],
};

/** Valid metric values for CVSS v3.0/v3.1 */
const CVSS_V3_VALID_VALUES: Record<string, readonly string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  PR: ["N", "L", "H"],
  UI: ["N", "R"],
  S: ["U", "C"],
  C: ["H", "L", "N"],
  I: ["H", "L", "N"],
  A: ["H", "L", "N"],
};

/** Valid metric values for CVSS v4.0 */
const CVSS_V4_VALID_VALUES: Record<string, readonly string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  AT: ["N", "P"],
  PR: ["N", "L", "H"],
  UI: ["N", "A", "P"],
  VC: ["H", "L", "N"],
  VI: ["H", "L", "N"],
  VA: ["H", "L", "N"],
  SC: ["H", "L", "N"],
  SI: ["H", "L", "N"],
  SA: ["H", "L", "N"],
};

// ─────────────────────────────────────────────────────
// §3  CVSS v2.0 Weight Tables
// ─────────────────────────────────────────────────────

const V2_AV_WEIGHTS: Record<string, number> = {
  N: 0.395,
  A: 0.646,
  L: 0.710,
  P: 1.0,
};

const V2_AC_WEIGHTS: Record<string, number> = {
  L: 0.35,
  M: 0.61,
  H: 0.71,
};

const V2_AU_WEIGHTS: Record<string, number> = {
  N: 0.704,
  S: 0.56,
  R: 0.45,
};

const V2_CIA_WEIGHTS: Record<string, number> = {
  N: 0.0,
  P: 0.275,
  C: 0.660,
};

// ─────────────────────────────────────────────────────
// §4  CVSS v3.x Weight Tables (from NVD spec)
// ─────────────────────────────────────────────────────

const V3_AV_WEIGHTS: Record<string, number> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
};

const V3_AC_WEIGHTS: Record<string, number> = {
  L: 0.77,
  H: 0.44,
};

const V3_UI_WEIGHTS: Record<string, number> = {
  N: 0.85,
  R: 0.62,
};

const V3_CIA_WEIGHTS: Record<string, number> = {
  H: 0.56,
  L: 0.22,
  N: 0.0,
};

const V3_PR_UNCHANGED: Record<string, number> = {
  N: 0.85,
  L: 0.62,
  H: 0.27,
};

const V3_PR_CHANGED: Record<string, number> = {
  N: 0.85,
  L: 0.68,
  H: 0.5,
};

// ─────────────────────────────────────────────────────
// §5  Version Detection
// ─────────────────────────────────────────────────────

/**
 * Detect CVSS version from vector string prefix.
 * Supports: CVSS:2.0, CVSS:3.0, CVSS:3.1, CVSS:4.0
 *
 * @param vector - The CVSS vector string
 * @returns Detected version or undefined if no valid prefix found
 */
export function detectCvssVersion(vector: string): CvssVersion | undefined {
  const trimmed = vector.trim();

  if (trimmed.startsWith("CVSS:4.0")) return "4.0";
  if (trimmed.startsWith("CVSS:3.1")) return "3.1";
  if (trimmed.startsWith("CVSS:3.0")) return "3.0";
  if (trimmed.startsWith("CVSS:2.0")) return "2.0";

  // Legacy v2 format (no prefix, but has Au metric)
  if (/\/Au:/.test(trimmed) && !trimmed.startsWith("CVSS:")) {
    return "2.0";
  }

  return undefined;
}

// ─────────────────────────────────────────────────────
// §6  Vector Parsing
// ─────────────────────────────────────────────────────

/**
 * Parse CVSS vector string into key-value metric pairs.
 *
 * @param vector - The CVSS vector string
 * @returns Record of metric abbreviations to their values
 */
function parseVectorMetrics(vector: string): Record<string, string> {
  const trimmed = vector.trim();
  const metrics: Record<string, string> = {};

  // Find the start of metrics
  // For versioned vectors (CVSS:3.1/AV:N/...), skip version prefix
  // For legacy vectors (AV:N/AC:L/Au:N/...), start from beginning
  let metricPart = trimmed;
  const versionMatch = trimmed.match(/^CVSS:\d+\.\d+(\/.*)$/);
  if (versionMatch) {
    metricPart = versionMatch[1]!;
  }

  // Split on /
  const pairs = metricPart.split("/");

  for (const pair of pairs) {
    const colonIdx = pair.indexOf(":");
    if (colonIdx === -1) continue;

    const key = pair.slice(0, colonIdx).trim();
    const value = pair.slice(colonIdx + 1).trim();

    if (key && value) {
      metrics[key] = value;
    }
  }

  return metrics;
}

// ─────────────────────────────────────────────────────
// §7  CVSS v2.0 Validation & Scoring
// ─────────────────────────────────────────────────────

/**
 * Validate CVSS v2.0 vector.
 */
function validateCvssV2(vector: string): CvssValidationResult {
  const errors: string[] = [];
  const trimmed = vector.trim();
  const metrics = parseVectorMetrics(vector);

  // Check version prefix (accept CVSS:2.0 prefix or legacy format with Au metric)
  if (!trimmed.startsWith("CVSS:2.0") && !/\/Au:/.test(trimmed)) {
    errors.push("Invalid CVSS v2.0 format: missing CVSS:2.0 prefix");
  }

  // Check required metrics
  for (const metric of CVSS_V2_REQUIRED_METRICS) {
    if (!(metric in metrics)) {
      errors.push(`Missing required metric: ${metric}`);
    } else {
      const validValues = CVSS_V2_VALID_VALUES[metric];
      const metricValue = metrics[metric];
      if (validValues && metricValue && !validValues.includes(metricValue)) {
        errors.push(`Invalid value for ${metric}: ${metricValue}. Valid: ${validValues.join(", ")}`);
      }
    }
  }

  // Check for unexpected metrics
  const allV2Metrics = new Set([...CVSS_V2_REQUIRED_METRICS, ...Object.keys(CVSS_V2_VALID_VALUES)]);
  for (const key of Object.keys(metrics)) {
    if (!allV2Metrics.has(key)) {
      errors.push(`Unexpected metric for CVSS v2.0: ${key}`);
    }
  }

  if (errors.length > 0) {
    return { isValid: false, version: "2.0", metrics, errors };
  }

  // Calculate score
  const score = calculateCvssV2Score(metrics);
  const severity = scoreToSeverity(score);

  return {
    isValid: true,
    version: "2.0",
    score,
    severity,
    metrics,
    errors: [],
  };
}

/**
 * Calculate CVSS v2.0 base score.
 *
 * @see https://www.first.org/cvss/v2/guide#3-2-1-base-metric-values
 */
function calculateCvssV2Score(metrics: Record<string, string>): number {
  const av = V2_AV_WEIGHTS[metrics.AV ?? "N"] ?? 0.395;
  const ac = V2_AC_WEIGHTS[metrics.AC ?? "M"] ?? 0.61;
  const au = V2_AU_WEIGHTS[metrics.Au ?? "R"] ?? 0.45;

  const impactSubScore =
    10.41 * (1 - (1 - (V2_CIA_WEIGHTS[metrics.C ?? "N"] ?? 0)) *
      (1 - (V2_CIA_WEIGHTS[metrics.I ?? "N"] ?? 0)) *
      (1 - (V2_CIA_WEIGHTS[metrics.A ?? "N"] ?? 0)));

  const impact = impactSubScore === 0 ? 0 : 1.176 * impactSubScore;

  const exploitability = 20 * av * ac * au;

  if (impact === 0) return 0.0;

  const baseScore = ((0.6 * impact + 0.4 * exploitability - 1.5) * 1.176);

  return Math.round(Math.min(Math.max(baseScore, 0), 10) * 10) / 10;
}

// ─────────────────────────────────────────────────────
// §8  CVSS v3.x Validation & Scoring
// ─────────────────────────────────────────────────────

/**
 * Validate CVSS v3.0 or v3.1 vector.
 */
function validateCvssV3(vector: string, version: "3.0" | "3.1"): CvssValidationResult {
  const errors: string[] = [];
  const metrics = parseVectorMetrics(vector);

  // Check required metrics
  for (const metric of CVSS_V3_REQUIRED_METRICS) {
    if (!(metric in metrics)) {
      errors.push(`Missing required metric: ${metric}`);
    } else {
      const validValues = CVSS_V3_VALID_VALUES[metric];
      const metricValue = metrics[metric];
      if (validValues && metricValue && !validValues.includes(metricValue)) {
        errors.push(`Invalid value for ${metric}: ${metricValue}. Valid: ${validValues.join(", ")}`);
      }
    }
  }

  // Check for unexpected metrics
  const allV3Metrics = new Set([...CVSS_V3_REQUIRED_METRICS, ...Object.keys(CVSS_V3_VALID_VALUES)]);
  for (const key of Object.keys(metrics)) {
    if (!allV3Metrics.has(key)) {
      errors.push(`Unexpected metric for CVSS ${version}: ${key}`);
    }
  }

  if (errors.length > 0) {
    return { isValid: false, version, metrics, errors };
  }

  // Calculate score
  const score = calculateCvssV3Score(metrics);
  const severity = scoreToSeverity(score);

  return {
    isValid: true,
    version,
    score,
    severity,
    metrics,
    errors: [],
  };
}

/**
 * Calculate CVSS v3.x base score.
 *
 * @see https://www.first.org/cvss/v3.1/specification-document#7-Metric-Values
 */
function calculateCvssV3Score(metrics: Record<string, string>): number {
  const av = V3_AV_WEIGHTS[metrics.AV ?? "N"] ?? 0;
  const ac = V3_AC_WEIGHTS[metrics.AC ?? "L"] ?? 0;
  const ui = V3_UI_WEIGHTS[metrics.UI ?? "N"] ?? 0;
  const s = metrics.S ?? "U";
  const prTable = s === "U" ? V3_PR_UNCHANGED : V3_PR_CHANGED;
  const pr = prTable[metrics.PR ?? "N"] ?? 0;

  const exploitability = 8.22 * av * ac * pr * ui;

  const ciaBase = 1 -
    (1 - (V3_CIA_WEIGHTS[metrics.C ?? "N"] ?? 0)) *
    (1 - (V3_CIA_WEIGHTS[metrics.I ?? "N"] ?? 0)) *
    (1 - (V3_CIA_WEIGHTS[metrics.A ?? "N"] ?? 0));

  const impact = s === "U"
    ? 6.42 * ciaBase
    : 7.52 * (ciaBase - 0.029) - 3.25 * Math.pow(ciaBase * 0.9731 - 0.02, 13);

  if (impact <= 0) return 0;

  const raw = s === "U"
    ? Math.min(impact + exploitability, 10)
    : Math.min(1.08 * (impact + exploitability), 10);

  // Round up to nearest 0.1 per NVD spec
  return Math.ceil((raw + 1e-10) * 10) / 10;
}

// ─────────────────────────────────────────────────────
// §9  CVSS v4.0 Validation
// ─────────────────────────────────────────────────────

/**
 * Validate CVSS v4.0 vector.
 *
 * CVSS v4.0 scoring is more complex and typically requires
 * Environmental and Threat metrics for full calculation.
 * For now, we validate the format and use a simplified
 * approximation based on the CVSS-BT (v3.1 base equivalent) score.
 */
function validateCvssV4(vector: string): CvssValidationResult {
  const errors: string[] = [];
  const metrics = parseVectorMetrics(vector);

  // Check required metrics
  for (const metric of CVSS_V4_REQUIRED_METRICS) {
    if (!(metric in metrics)) {
      errors.push(`Missing required metric: ${metric}`);
    } else {
      const validValues = CVSS_V4_VALID_VALUES[metric];
      const metricValue = metrics[metric];
      if (validValues && metricValue && !validValues.includes(metricValue)) {
        errors.push(`Invalid value for ${metric}: ${metricValue}. Valid: ${validValues.join(", ")}`);
      }
    }
  }

  // Check for unexpected metrics (v4.0 has additional optional metrics)
  const allV4Metrics = new Set([...CVSS_V4_REQUIRED_METRICS, ...Object.keys(CVSS_V4_VALID_VALUES)]);
  for (const key of Object.keys(metrics)) {
    if (!allV4Metrics.has(key)) {
      // CVSS v4.0 allows additional metrics; we just warn but don't error
    }
  }

  if (errors.length > 0) {
    return { isValid: false, version: "4.0", metrics, errors };
  }

  // Calculate approximate score using v3.1 equivalent metrics
  const score = calculateCvssV4ApproximateScore(metrics);
  const severity = scoreToSeverity(score);

  return {
    isValid: true,
    version: "4.0",
    score,
    severity,
    metrics,
    errors: [],
  };
}

/**
 * Calculate approximate CVSS v4.0 score.
 *
 * CVSS v4.0 uses a different scoring model, but we can approximate
 * using the base metric equivalence. The full CVSS-B (base) score
 * in v4.0 uses VC, VI, VA, SC, SI, SA metrics.
 */
function calculateCvssV4ApproximateScore(metrics: Record<string, string>): number {
  // Map v4 metrics to v3.1 equivalent for approximation
  const av = V3_AV_WEIGHTS[metrics.AV ?? "N"] ?? 0;
  const ac = V3_AC_WEIGHTS[metrics.AC ?? "L"] ?? 0;
  const ui = metrics.UI === "N" ? 0.85 : 0.62; // Simplified

  // For v4.0, we use VC, VI, VA instead of C, I, A
  const vc = V3_CIA_WEIGHTS[metrics.VC ?? "N"] ?? 0;
  const vi = V3_CIA_WEIGHTS[metrics.VI ?? "N"] ?? 0;
  const va = V3_CIA_WEIGHTS[metrics.VA ?? "N"] ?? 0;

  const ciaBase = 1 - (1 - vc) * (1 - vi) * (1 - va);

  const impact = 6.42 * ciaBase;
  const exploitability = 8.22 * av * ac * 0.85 * ui; // Approximate PR=N

  const raw = Math.min(impact + exploitability, 10);

  // Round up to nearest 0.1
  return Math.ceil((raw + 1e-10) * 10) / 10;
}

// ─────────────────────────────────────────────────────
// §10  Main Validator Class
// ─────────────────────────────────────────────────────

/**
 * CVSS Vector Validator
 *
 * Validates and parses CVSS vectors for versions 2.0, 3.0, 3.1, and 4.0.
 * Provides comprehensive validation including format checking, metric
 * validation, and score calculation.
 *
 * @example
 * ```typescript
 * const validator = new CvssValidator();
 *
 * // Validate a CVSS 3.1 vector
 * const result = validator.validate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 * console.log(result.isValid); // true
 * console.log(result.score); // 9.8
 * console.log(result.severity); // "critical"
 *
 * // Get full vector info
 * const info = validator.parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 * console.log(info.metrics.attackVector); // "N"
 * ```
 */
export class CvssValidator {
  /**
   * Validate a CVSS vector string.
   *
   * @param vector - The CVSS vector string to validate
   * @returns Validation result with score, severity, and any errors
   */
  validate(vector: string): CvssValidationResult {
    if (!vector || typeof vector !== "string") {
      return {
        isValid: false,
        errors: ["Invalid input: vector must be a non-empty string"],
      };
    }

    const trimmed = vector.trim();
    if (trimmed.length === 0) {
      return {
        isValid: false,
        errors: ["Invalid input: vector cannot be empty or blank"],
      };
    }

    const version = detectCvssVersion(trimmed);
    if (!version) {
      return {
        isValid: false,
        errors: [
          "Unknown CVSS version. Supported versions: CVSS:2.0, CVSS:3.0, CVSS:3.1, CVSS:4.0",
        ],
      };
    }

    switch (version) {
      case "2.0":
        return validateCvssV2(trimmed);
      case "3.0":
      case "3.1":
        return validateCvssV3(trimmed, version);
      case "4.0":
        return validateCvssV4(trimmed);
      default:
        return {
          isValid: false,
          errors: [`Unsupported CVSS version: ${version}`],
        };
    }
  }

  /**
   * Parse a CVSS vector and return full information.
   *
   * @param vector - The CVSS vector string to parse
   * @returns Full vector information including metrics, score, and validation status
   */
  parseVector(vector: string): CvssVectorInfo {
    const result = this.validate(vector);
    const version = result.version ?? "3.1";

    const metricsMap: Record<string, string> = result.metrics ?? {};
    const metrics = this.expandMetricNames(metricsMap, version);

    return {
      version,
      score: result.score ?? 0,
      severity: result.severity ?? "unknown",
      vector: vector.trim(),
      metrics,
      isValid: result.isValid,
      validationErrors: result.isValid ? undefined : result.errors,
    };
  }

  /**
   * Check if a vector is valid without computing score.
   *
   * @param vector - The CVSS vector string to check
   * @returns True if the vector is valid
   */
  isValid(vector: string): boolean {
    return this.validate(vector).isValid;
  }

  /**
   * Get the CVSS version from a vector string.
   *
   * @param vector - The CVSS vector string
   * @returns The detected CVSS version, or undefined if not recognized
   */
  getVersion(vector: string): CvssVersion | undefined {
    return detectCvssVersion(vector);
  }

  /**
   * Expand abbreviated metric names to full names.
   *
   * @param metrics - Parsed metric key-value pairs
   * @param version - CVSS version
   * @returns Record with expanded metric names
   */
  private expandMetricNames(
    metrics: Record<string, string>,
    version: CvssVersion,
  ): Record<string, string> {
    const nameMap: Record<string, string> = {
      AV: "attackVector",
      AC: "attackComplexity",
      PR: "privilegesRequired",
      UI: "userInteraction",
      S: "scope",
      C: "confidentiality",
      I: "integrity",
      A: "availability",
      Au: "authentication",
      AT: "attackRequirements",
      VC: "vulnerableConfidentiality",
      VI: "vulnerableIntegrity",
      VA: "vulnerableAvailability",
      SC: "subsequentConfidentiality",
      SI: "subsequentIntegrity",
      SA: "subsequentAvailability",
    };

    const expanded: Record<string, string> = {};
    for (const [key, value] of Object.entries(metrics)) {
      const fullName = nameMap[key] ?? key;
      expanded[fullName] = value;
    }

    return expanded;
  }

  /**
   * Get human-readable labels for metric values.
   *
   * @param metric - The metric abbreviation (e.g., "AV")
   * @param value - The metric value (e.g., "N")
   * @returns Human-readable label
   */
  getMetricLabel(metric: string, value: string): string {
    const labels: Record<string, Record<string, string>> = {
      AV: {
        N: "Network",
        A: "Adjacent",
        L: "Local",
        P: "Physical",
      },
      AC: {
        L: "Low",
        H: "High",
      },
      PR: {
        N: "None",
        L: "Low",
        H: "High",
      },
      UI: {
        N: "None",
        R: "Required",
        A: "Active",
        P: "Passive",
      },
      S: {
        U: "Unchanged",
        C: "Changed",
      },
      C: {
        H: "High",
        L: "Low",
        N: "None",
      },
      I: {
        H: "High",
        L: "Low",
        N: "None",
      },
      A: {
        H: "High",
        L: "Low",
        N: "None",
      },
      Au: {
        N: "None",
        S: "Single",
        R: "Multiple",
      },
      AT: {
        N: "None",
        P: "Present",
      },
      VC: {
        H: "High",
        L: "Low",
        N: "None",
      },
      VI: {
        H: "High",
        L: "Low",
        N: "None",
      },
      VA: {
        H: "High",
        L: "Low",
        N: "None",
      },
      SC: {
        H: "High",
        L: "Low",
        N: "None",
      },
      SI: {
        H: "High",
        L: "Low",
        N: "None",
      },
      SA: {
        H: "High",
        L: "Low",
        N: "None",
      },
    };

    return labels[metric]?.[value] ?? value;
  }
}

// ─────────────────────────────────────────────────────
// §11  Convenience Functions
// ─────────────────────────────────────────────────────

/** Singleton validator instance for convenience */
const defaultValidator = new CvssValidator();

/**
 * Validate a CVSS vector string.
 *
 * @param vector - The CVSS vector string to validate
 * @returns Validation result
 */
export function validateCvssVector(vector: string): CvssValidationResult {
  return defaultValidator.validate(vector);
}

/**
 * Parse a CVSS vector and return full information.
 *
 * @param vector - The CVSS vector string to parse
 * @returns Full vector information
 */
export function parseCvssVector(vector: string): CvssVectorInfo {
  return defaultValidator.parseVector(vector);
}

/**
 * Check if a CVSS vector is valid.
 *
 * @param vector - The CVSS vector string to check
 * @returns True if valid
 */
export function isCvssVectorValid(vector: string): boolean {
  return defaultValidator.isValid(vector);
}

/**
 * Get the CVSS version from a vector string.
 *
 * @param vector - The CVSS vector string
 * @returns Detected version or undefined
 */
export function getCvssVersion(vector: string): CvssVersion | undefined {
  return defaultValidator.getVersion(vector);
}
