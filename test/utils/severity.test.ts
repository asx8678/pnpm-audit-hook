import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mapSeverity, severityRank, SEVERITY_RANK } from "../../src/utils/severity";
import type { Severity } from "../../src/types";

describe("mapSeverity", () => {
  it("maps valid severities correctly", () => {
    assert.equal(mapSeverity("critical"), "critical");
    assert.equal(mapSeverity("high"), "high");
    assert.equal(mapSeverity("medium"), "medium");
    assert.equal(mapSeverity("low"), "low");
  });

  it("maps 'moderate' to 'medium'", () => {
    assert.equal(mapSeverity("moderate"), "medium");
  });

  it("is case insensitive", () => {
    assert.equal(mapSeverity("CRITICAL"), "critical");
    assert.equal(mapSeverity("High"), "high");
    assert.equal(mapSeverity("MEDIUM"), "medium");
    assert.equal(mapSeverity("LOW"), "low");
    assert.equal(mapSeverity("MODERATE"), "medium");
    assert.equal(mapSeverity("Moderate"), "medium");
  });

  it("returns 'unknown' for invalid inputs", () => {
    assert.equal(mapSeverity("invalid"), "unknown");
    assert.equal(mapSeverity(""), "unknown");
    assert.equal(mapSeverity("severe"), "unknown");
    assert.equal(mapSeverity("warning"), "unknown");
  });

  it("returns 'unknown' for undefined input", () => {
    assert.equal(mapSeverity(undefined), "unknown");
  });
});

describe("severityRank", () => {
  it("returns correct rank for each severity", () => {
    assert.equal(severityRank("critical"), 4);
    assert.equal(severityRank("high"), 3);
    assert.equal(severityRank("medium"), 2);
    assert.equal(severityRank("low"), 1);
    assert.equal(severityRank("unknown"), 0);
  });

  it("maintains correct ordering (critical > high > medium > low > unknown)", () => {
    assert.ok(severityRank("critical") > severityRank("high"));
    assert.ok(severityRank("high") > severityRank("medium"));
    assert.ok(severityRank("medium") > severityRank("low"));
    assert.ok(severityRank("low") > severityRank("unknown"));
  });

  it("can be used for sorting severities", () => {
    const severities: Severity[] = ["low", "critical", "unknown", "high", "medium"];
    const sorted = [...severities].sort((a, b) => severityRank(b) - severityRank(a));
    assert.deepEqual(sorted, ["critical", "high", "medium", "low", "unknown"]);
  });
});

describe("SEVERITY_RANK", () => {
  it("contains all severity levels", () => {
    const expectedKeys: Severity[] = ["critical", "high", "medium", "low", "unknown"];
    assert.deepEqual(Object.keys(SEVERITY_RANK).sort(), expectedKeys.sort());
  });
});
