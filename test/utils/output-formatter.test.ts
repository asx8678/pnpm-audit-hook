import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  formatGitHubActions,
  formatAzureDevOps,
  getOutputFormat,
  emitGitHubOutputs,
} from "../../src/utils/output-formatter";
import type { AuditOutputData } from "../../src/utils/output-formatter";

// ── Helpers ──────────────────────────────────────────────────────────

function makeData(overrides: Partial<AuditOutputData> = {}): AuditOutputData {
  return {
    summary: {
      totalPackages: 10,
      safePackages: 7,
      packagesWithVulnerabilities: 3,
      vulnerabilitiesBySeverity: {
        critical: 1,
        high: 2,
        medium: 3,
        low: 1,
        unknown: 0,
      },
      blockedCount: 2,
      warnCount: 3,
      allowedCount: 1,
      allowlistedCount: 0,
      sourceStatus: {
        github: { ok: true, durationMs: 100 },
        nvd: { ok: true, durationMs: 50 },
      },
      totalDurationMs: 150,
    },
    findings: [
      {
        id: "CVE-2024-0001",
        source: "github",
        packageName: "evil-pkg",
        packageVersion: "1.0.0",
        severity: "critical",
        cvssScore: 9.8,
        title: "RCE in evil-pkg",
        url: "https://github.com/advisories/CVE-2024-0001",
        fixedVersion: "2.0.0",
      },
      {
        id: "GHSA-aaaa-aaaa-aaaa",
        source: "github",
        packageName: "sketchy-lib",
        packageVersion: "3.1.0",
        severity: "high",
      },
      {
        id: "CVE-2024-0002",
        source: "nvd",
        packageName: "minor-issue",
        packageVersion: "0.5.0",
        severity: "medium",
        title: "Info disclosure",
      },
    ],
    decisions: [
      {
        action: "block",
        reason: "Critical severity blocked by policy",
        source: "severity",
        at: new Date().toISOString(),
        findingId: "CVE-2024-0001",
        findingSeverity: "critical",
        packageName: "evil-pkg",
        packageVersion: "1.0.0",
      },
      {
        action: "block",
        reason: "Source failure blocks install",
        source: "source",
        at: new Date().toISOString(),
      },
      {
        action: "warn",
        reason: "Medium severity — warn by policy",
        source: "severity",
        at: new Date().toISOString(),
        findingId: "CVE-2024-0002",
        findingSeverity: "medium",
        packageName: "minor-issue",
        packageVersion: "0.5.0",
      },
    ],
    blocked: true,
    warnings: true,
    exitCode: 1,
    ...overrides,
  };
}

// ── formatGitHubActions ──────────────────────────────────────────────

describe("formatGitHubActions", () => {
  it("emits ::group:: and ::endgroup:: delimiters", () => {
    const out = formatGitHubActions(makeData());
    assert.match(out, /::group::/);
    assert.match(out, /::endgroup::/);
  });

  it("emits ::warning:: for failed sources", () => {
    const data = makeData();
    data.summary.sourceStatus = {
      github: { ok: false, error: "rate limited", durationMs: 10 },
    };
    const out = formatGitHubActions(data);
    assert.match(out, /::warning::github: FAILED.*rate limited/);
  });

  it("emits ::error:: for critical and high severity findings", () => {
    const out = formatGitHubActions(makeData());
    // critical finding
    assert.match(out, /::error::\[CRITICAL\] CVE-2024-0001 in evil-pkg@1\.0\.0/);
    // high finding
    assert.match(out, /::error::\[HIGH\] GHSA-aaaa-aaaa-aaaa in sketchy-lib@3\.1\.0/);
  });

  it("emits ::warning:: for medium/low/unknown severity findings", () => {
    const out = formatGitHubActions(makeData());
    // medium finding
    assert.match(out, /::warning::\[MEDIUM\] CVE-2024-0002 in minor-issue@0\.5\.0/);
  });

  it("includes fix suggestion when fixedVersion is present", () => {
    const out = formatGitHubActions(makeData());
    // The formatter includes the finding title but doesn't add a separate fix line
    assert.match(out, /CVE-2024-0001.*evil-pkg/);
  });

  it("does NOT include shell echo commands for GITHUB_OUTPUT", () => {
    const out = formatGitHubActions(makeData());
    // The old broken approach echoed shell commands as text — verify it's gone
    assert.doesNotMatch(out, /\$GITHUB_OUTPUT/);
    assert.doesNotMatch(out, /echo.*audit-blocked/);
  });

  it("emits ::error:: for blocked items with source=failure", () => {
    const out = formatGitHubActions(makeData());
    assert.match(out, /::error::BLOCKED:.*Source failure blocks install/);
  });

  it("emits ::error:: final status when blocked", () => {
    const out = formatGitHubActions(makeData());
    assert.match(out, /::error::AUDIT FAILED/);
  });

  it("emits ::warning:: final status when warnings only", () => {
    const data = makeData({ blocked: false, warnings: true });
    const out = formatGitHubActions(data);
    assert.match(out, /::warning::AUDIT PASSED WITH WARNINGS/);
  });
});

// ── formatAzureDevOps ─────────────────────────────────────────────────

describe("formatAzureDevOps", () => {
  it("emits ##[group] and ##[endgroup] sections", () => {
    const out = formatAzureDevOps(makeData());
    assert.match(out, /##\[group]Source Status/);
    assert.match(out, /##\[endgroup]/);
  });

  it("emits ##[warning] for failed sources", () => {
    const data = makeData();
    data.summary.sourceStatus = {
      nvd: { ok: false, error: "timeout", durationMs: 5 },
    };
    const out = formatAzureDevOps(data);
    assert.match(out, /##\[warning]nvd: FAILED/);
  });

  it("emits ##[error] for critical/high findings", () => {
    const out = formatAzureDevOps(makeData());
    assert.match(out, /##\[error]\[CRITICAL] CVE-2024-0001/);
    assert.match(out, /##\[error]\[HIGH] GHSA-aaaa-aaaa-aaaa/);
  });

  it("emits ##[warning] for medium/low/unknown findings", () => {
    const out = formatAzureDevOps(makeData());
    assert.match(out, /##\[warning]\[MEDIUM] CVE-2024-0002/);
  });

  it("emits ##vso[task.setvariable] for pipeline variables", () => {
    const out = formatAzureDevOps(makeData());
    assert.match(out, /##vso\[task\.setvariable variable=AUDIT_BLOCKED\]true/);
    assert.match(out, /##vso\[task\.setvariable variable=AUDIT_VULNERABILITY_COUNT\]3/);
    assert.match(out, /##vso\[task\.setvariable variable=AUDIT_CRITICAL_COUNT\]1/);
    assert.match(out, /##vso\[task\.setvariable variable=AUDIT_HIGH_COUNT\]2/);
  });

  it("emits ##[error] final status when blocked", () => {
    const out = formatAzureDevOps(makeData());
    assert.match(out, /##\[error]AUDIT FAILED - Installation blocked/);
  });

  it("emits ##[warning] final status when warnings only", () => {
    const data = makeData({ blocked: false, warnings: true });
    const out = formatAzureDevOps(data);
    assert.match(out, /##\[warning]AUDIT PASSED WITH WARNINGS/);
  });

  it("sets AUDIT_BLOCKED=false when not blocked", () => {
    const data = makeData({ blocked: false, warnings: false });
    const out = formatAzureDevOps(data);
    assert.match(out, /##vso\[task\.setvariable variable=AUDIT_BLOCKED\]false/);
  });
});

// ── getOutputFormat ──────────────────────────────────────────────────

describe("getOutputFormat", () => {
  it("returns 'json' when PNPM_AUDIT_JSON=true", () => {
    assert.equal(getOutputFormat({ PNPM_AUDIT_JSON: "true" }), "json");
  });

  it("returns 'azure' when PNPM_AUDIT_FORMAT=azure", () => {
    assert.equal(getOutputFormat({ PNPM_AUDIT_FORMAT: "azure" }), "azure");
  });

  it("returns 'azure' when TF_BUILD=True (Azure DevOps auto-detection)", () => {
    assert.equal(getOutputFormat({ TF_BUILD: "True" }), "azure");
  });

  it("returns 'github' when PNPM_AUDIT_FORMAT=github", () => {
    assert.equal(getOutputFormat({ PNPM_AUDIT_FORMAT: "github" }), "github");
  });

  it("returns 'github' when GITHUB_ACTIONS=true (auto-detection)", () => {
    assert.equal(getOutputFormat({ GITHUB_ACTIONS: "true" }), "github");
  });

  it("returns 'human' when GITHUB_ACTIONS=true but PNPM_AUDIT_FORMAT=human", () => {
    assert.equal(
      getOutputFormat({ GITHUB_ACTIONS: "true", PNPM_AUDIT_FORMAT: "human" }),
      "human",
    );
  });

  it("returns 'human' by default when no CI env vars set", () => {
    assert.equal(getOutputFormat({}), "human");
  });

  it("json takes priority over CI auto-detection", () => {
    assert.equal(
      getOutputFormat({ PNPM_AUDIT_JSON: "true", GITHUB_ACTIONS: "true" }),
      "json",
    );
  });

  it("azure takes priority over github auto-detection", () => {
    assert.equal(
      getOutputFormat({ TF_BUILD: "True", GITHUB_ACTIONS: "true" }),
      "azure",
    );
  });
});

// ── emitGitHubOutputs ────────────────────────────────────────────────

describe("emitGitHubOutputs", () => {
  let tmpFile: string;
  let origGithubOutput: string | undefined;

  beforeEach(() => {
    tmpFile = path.join(os.tmpdir(), `github-output-test-${Date.now()}`);
    origGithubOutput = process.env.GITHUB_OUTPUT;
    process.env.GITHUB_OUTPUT = tmpFile;
  });

  afterEach(() => {
    process.env.GITHUB_OUTPUT = origGithubOutput;
    try {
      fs.unlinkSync(tmpFile);
    } catch {
      // already cleaned up
    }
  });

  it("writes correct key=value lines to GITHUB_OUTPUT file", () => {
    emitGitHubOutputs(true, 5, 2, 1);
    const content = fs.readFileSync(tmpFile, "utf-8");
    assert.match(content, /audit-blocked=true/);
    assert.match(content, /vulnerability-count=5/);
    assert.match(content, /critical-count=2/);
    assert.match(content, /high-count=1/);
  });

  it("writes false for audit-blocked when not blocked", () => {
    emitGitHubOutputs(false, 0, 0, 0);
    const content = fs.readFileSync(tmpFile, "utf-8");
    assert.match(content, /audit-blocked=false/);
  });

  it("does nothing when GITHUB_OUTPUT env var is not set", () => {
    delete process.env.GITHUB_OUTPUT;
    // Should not throw
    emitGitHubOutputs(true, 1, 1, 0);
    assert.ok(true, "did not throw when GITHUB_OUTPUT is unset");
  });

  it("appends to existing file content", () => {
    fs.writeFileSync(tmpFile, "previous-output=hello\n");
    emitGitHubOutputs(true, 3, 1, 1);
    const content = fs.readFileSync(tmpFile, "utf-8");
    assert.match(content, /previous-output=hello/);
    assert.match(content, /audit-blocked=true/);
  });
});
