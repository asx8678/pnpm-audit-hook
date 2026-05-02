/**
 * Enhanced dependency chain analyzer.
 *
 * Combines CVSS risk scoring with transitive chain analysis to provide:
 * - Severity propagation (adjusts severity based on chain context)
 * - Environmental risk scoring (CVSS + chain breadth/depth/exploitability)
 * - Rich vulnerability context for reporting and policy decisions
 */

import type {
  DependencyGraph,
  VulnerabilityFinding,
  VulnerabilityChainContext,
  CvssFindingDetails,
  RiskFactor,
  Severity,
} from "../../types.js";
import {
  traceDependencyChain,
  traceAllDependencyChains,
  analyzeImpact,
} from "./graph-builder.js";
import { parseCvssV3, scoreToSeverity } from "../cvss.js";
import { severityRank } from "../severity.js";

// ─────────────────────────────────────────────────────
// Section 1: Severity Propagation
// ─────────────────────────────────────────────────────

/**
 * Propagate severity through the dependency chain.
 *
 * Transitive dependencies are generally lower-risk than direct ones because:
 * - They are further from the application control surface
 * - Patching requires upstream updates
 * - The blast radius depends on chain depth and breadth
 *
 * Propagation rules:
 * - Direct dependency: no adjustment (full severity)
 * - Transitive, depth <= 2: downgrade by 0 levels (close to surface)
 * - Transitive, depth 3-5: downgrade by 1 level
 * - Transitive, depth > 5: downgrade by 1 level, but never below "low"
 * - Dev-only transitive: always downgrade by 1 extra level
 */
export function propagateSeverity(
  baseSeverity: Severity,
  chainDepth: number,
  isDirect: boolean,
  isDevOnly: boolean,
): Severity {
  if (isDirect) return baseSeverity;

  const rank = severityRank(baseSeverity);
  if (rank <= 1) return baseSeverity; // already "low" or "unknown"

  let downgrade = 0;

  // Depth-based downgrade
  if (chainDepth <= 2) {
    downgrade = 0; // very close to surface, full severity
  } else if (chainDepth <= 5) {
    downgrade = 1;
  } else {
    downgrade = 1; // deep chains get a downgrade, but cap at 1 level
  }

  // Extra downgrade for dev-only transitive dependencies
  if (isDevOnly) {
    downgrade += 1;
  }

  const newRank = Math.max(1, rank - downgrade);
  const SEVERITY_BY_RANK: Severity[] = ["low", "low", "medium", "high", "critical"];
  return SEVERITY_BY_RANK[newRank] ?? "unknown";
}

// ─────────────────────────────────────────────────────
// Section 2: Risk Factor Computation
// ─────────────────────────────────────────────────────

/** Weight constants for composite risk scoring */
const WEIGHTS = {
  cvss: 0.50,
  chainDepth: 0.10,
  breadth: 0.10,
  fixAvailable: 0.15,
  exploitability: 0.15,
} as const;

interface RiskScoringInput {
  cvssScore: number;
  chainDepth: number;
  breadth: number;
  isDirect: boolean;
  fixAvailable: boolean;
  isDevOnly: boolean;
  exploitabilityScore: number; // 0-1 scale
}

/** Compute individual risk factors and the composite score. */
function computeRiskFactors(input: RiskScoringInput): { factors: RiskFactor[]; composite: number } {
  const factors: RiskFactor[] = [];
  let composite = 0;

  // CVSS Base Score factor
  const cvssFactor: RiskFactor = {
    name: "cvss-base",
    description: `CVSS v3 base score: ${input.cvssScore}/10`,
    weight: WEIGHTS.cvss,
    score: input.cvssScore,
  };
  factors.push(cvssFactor);
  composite += cvssFactor.weight * cvssFactor.score;

  // Chain depth factor (deeper = riskier, capped at 10)
  const depthScore = Math.min(10, input.chainDepth * 1.5);
  const depthFactor: RiskFactor = {
    name: "chain-depth",
    description: `Dependency chain depth: ${input.chainDepth} level${input.chainDepth !== 1 ? "s" : ""} from direct dependency`,
    weight: WEIGHTS.chainDepth,
    score: depthScore,
  };
  factors.push(depthFactor);
  composite += depthFactor.weight * depthFactor.score;

  // Breadth factor (wider blast radius = riskier)
  const breadthScore = Math.min(10, Math.log2(input.breadth + 1) * 3);
  const breadthFactor: RiskFactor = {
    name: "blast-radius",
    description: `${input.breadth} package${input.breadth !== 1 ? "s" : ""} directly depend on this vulnerable package`,
    weight: WEIGHTS.breadth,
    score: breadthScore,
  };
  factors.push(breadthFactor);
  composite += breadthFactor.weight * breadthFactor.score;

  // Fix availability factor (fix available = lower risk)
  const fixScore = input.fixAvailable ? 2.0 : 8.0;
  const fixFactor: RiskFactor = {
    name: "fix-availability",
    description: input.fixAvailable
      ? "A patched version is available"
      : "No fix available - manual remediation required",
    weight: WEIGHTS.fixAvailable,
    score: fixScore,
  };
  factors.push(fixFactor);
  composite += fixFactor.weight * fixFactor.score;

  // Exploitability factor
  const exploitScore = input.exploitabilityScore * 10;
  const exploitFactor: RiskFactor = {
    name: "exploitability",
    description: `Exploitability: ${Math.round(input.exploitabilityScore * 100)}% (based on CVSS attack vector and user interaction)`,
    weight: WEIGHTS.exploitability,
    score: exploitScore,
  };
  factors.push(exploitFactor);
  composite += exploitFactor.weight * exploitFactor.score;

  // Dev-only bonus adjustment
  if (input.isDevOnly) {
    const devFactor: RiskFactor = {
      name: "dev-only",
      description: "Package is a dev-only dependency (reduced production exposure)",
      weight: 0,
      score: 0,
    };
    factors.push(devFactor);
    composite *= 0.7; // 30% reduction for dev-only
  }

  return { factors, composite: Math.round(Math.min(10, composite) * 10) / 10 };
}

// ─────────────────────────────────────────────────────
// Section 3: Exploitability Estimation
// ─────────────────────────────────────────────────────

/**
 * Estimate exploitability score (0-1) from CVSS metrics.
 * Higher score = easier to exploit.
 */
function estimateExploitability(cvssVector?: string): number {
  if (!cvssVector) return 0.5; // default medium

  const parsed = parseCvssV3(cvssVector);
  if (!parsed) return 0.5;

  const { metrics } = parsed;
  let score = 0;

  // Attack vector contribution (0-0.4)
  const avScores: Record<string, number> = { N: 0.4, A: 0.3, L: 0.2, P: 0.1 };
  score += avScores[metrics.attackVector] ?? 0.2;

  // Attack complexity contribution (0-0.3)
  const acScores: Record<string, number> = { L: 0.3, H: 0.1 };
  score += acScores[metrics.attackComplexity] ?? 0.2;

  // Privileges required (0-0.2)
  const prScores: Record<string, number> = { N: 0.2, L: 0.1, H: 0.05 };
  score += prScores[metrics.privilegesRequired] ?? 0.1;

  // User interaction (0-0.1)
  const uiScores: Record<string, number> = { N: 0.1, R: 0.05 };
  score += uiScores[metrics.userInteraction] ?? 0.05;

  return Math.min(1, score);
}

// ─────────────────────────────────────────────────────
// Section 4: Main Analysis Function
// ─────────────────────────────────────────────────────

/**
 * Analyze a vulnerability finding in the context of the dependency graph.
 *
 * Enriches the finding with:
 * - Chain context (depth, paths, affected count, propagated severity)
 * - CVSS details (parsed metrics, exploitability label)
 * - Risk factors and composite score
 */
export function analyzeVulnerability(
  finding: VulnerabilityFinding,
  graph: DependencyGraph,
): VulnerabilityFinding {
  const findingKey = `${finding.packageName}@${finding.packageVersion}`;

  // Get existing chain or trace a new one
  let chain = finding.dependencyChain ?? null;
  if (!chain) {
    chain = traceDependencyChain(graph, findingKey);
  }

  // Determine directness
  const isDirect = graph.directKeys.has(findingKey);

  // Chain depth (0 for direct, length-1 for transitive)
  const chainDepth = chain ? Math.max(0, chain.length - 1) : 0;

  // Get all chains for path count
  const allChains = traceAllDependencyChains(graph, findingKey);
  const numberOfPaths = allChains.length || (isDirect ? 1 : 0);

  // Identify direct ancestors
  const directAncestors: string[] = [];
  if (!isDirect) {
    for (const path of allChains) {
      if (path.length > 0) {
        const ancestor = path[0]!;
        if (graph.directKeys.has(ancestor) && !directAncestors.includes(ancestor)) {
          directAncestors.push(ancestor);
        }
      }
    }
  }

  // Determine if dev-only
  const node = graph.nodes.get(findingKey);
  const isDevOnly = node?.isDev ?? false;

  // Impact analysis
  const impact = analyzeImpact(graph, findingKey);

  // Propagate severity
  const propagatedSeverity = propagateSeverity(
    finding.severity,
    chainDepth,
    isDirect,
    isDevOnly,
  );

  // Fix availability
  const fixAvailable = !!finding.fixedVersion;

  // CVSS details
  let cvssDetails: CvssFindingDetails | undefined;
  let cvssScore = finding.cvssScore;

  if (finding.cvssVector) {
    const parsed = parseCvssV3(finding.cvssVector);
    if (parsed) {
      cvssDetails = {
        score: parsed.score,
        severity: parsed.severity,
        attackVector: parsed.metrics.attackVector,
        attackComplexity: parsed.metrics.attackComplexity,
        privilegesRequired: parsed.metrics.privilegesRequired,
        userInteraction: parsed.metrics.userInteraction,
        scope: parsed.metrics.scope,
        confidentiality: parsed.metrics.confidentiality,
        integrity: parsed.metrics.integrity,
        availability: parsed.metrics.availability,
        exploitabilityLabel: parsed.exploitabilityLabel,
      };
      cvssScore = parsed.score;
    }
  } else if (cvssScore != null) {
    // If we only have a numeric score, use it directly
    cvssDetails = {
      score: cvssScore,
      severity: scoreToSeverity(cvssScore),
      attackVector: "unknown",
      attackComplexity: "unknown",
      privilegesRequired: "unknown",
      userInteraction: "unknown",
      scope: "unknown",
      confidentiality: "unknown",
      integrity: "unknown",
      availability: "unknown",
      exploitabilityLabel: "unknown",
    };
  }

  // Compute risk factors
  const exploitabilityScore = estimateExploitability(finding.cvssVector);
  const effectiveCvss = cvssScore ?? severityRank(finding.severity) * 2.5;

  const { factors, composite } = computeRiskFactors({
    cvssScore: effectiveCvss,
    chainDepth,
    breadth: impact.breadth,
    isDirect,
    fixAvailable,
    isDevOnly,
    exploitabilityScore,
  });

  // Build chain context
  const chainContext: VulnerabilityChainContext = {
    isDirect,
    chainDepth,
    numberOfPaths,
    totalAffected: impact.totalDependents,
    propagatedSeverity,
    fixAvailable,
    isDevOnly,
    directAncestors,
    riskFactors: factors,
    compositeRiskScore: composite,
  };

  // Return enriched finding
  return {
    ...finding,
    cvssScore,
    chainContext,
    cvssDetails,
  };
}

/**
 * Batch-analyze all findings against the dependency graph.
 */
export function analyzeAllVulnerabilities(
  findings: VulnerabilityFinding[],
  graph: DependencyGraph,
): VulnerabilityFinding[] {
  return findings.map(f => analyzeVulnerability(f, graph));
}

/**
 * Sort findings by composite risk score (descending).
 * Higher risk = should be addressed first.
 */
export function sortByRisk(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  return [...findings].sort((a, b) => {
    const scoreA = a.chainContext?.compositeRiskScore ?? severityRank(a.severity) * 2.5;
    const scoreB = b.chainContext?.compositeRiskScore ?? severityRank(b.severity) * 2.5;
    return scoreB - scoreA;
  });
}
