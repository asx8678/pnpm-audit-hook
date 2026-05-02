import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  cvssV3VectorToSeverity,
  cvssV3ToScore,
  scoreToSeverity,
  parseCvssV3,
} from "../../src/utils/cvss";

describe("cvssV3VectorToSeverity", () => {
  describe("valid CVSS 3.1 vectors", () => {
    it("returns 'critical' for score >= 9.0", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      assert.equal(cvssV3VectorToSeverity(vector), "critical");
    });

    it("returns 'high' for score >= 7.0 and < 9.0", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
      assert.equal(cvssV3VectorToSeverity(vector), "high");
    });

    it("returns 'medium' for score >= 4.0 and < 7.0", () => {
      const vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L";
      assert.equal(cvssV3VectorToSeverity(vector), "medium");
    });

    it("returns 'low' for score > 0 and < 4.0", () => {
      const vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L";
      assert.equal(cvssV3VectorToSeverity(vector), "low");
    });
  });

  describe("valid CVSS 3.0 vectors", () => {
    it("handles CVSS 3.0 prefix", () => {
      const vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      assert.equal(cvssV3VectorToSeverity(vector), "critical");
    });
  });

  describe("scope changed (S:C) vectors", () => {
    it("calculates correctly with changed scope", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
      assert.equal(cvssV3VectorToSeverity(vector), "critical");
    });
  });

  describe("invalid vectors", () => {
    it("returns 'unknown' for non-CVSS:3.x prefix", () => {
      assert.equal(cvssV3VectorToSeverity("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"), "unknown");
      assert.equal(cvssV3VectorToSeverity("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), "unknown");
    });

    it("returns 'unknown' for empty string", () => {
      assert.equal(cvssV3VectorToSeverity(""), "unknown");
    });

    it("returns 'unknown' for malformed vectors", () => {
      assert.equal(cvssV3VectorToSeverity("CVSS:3.1"), "unknown");
      assert.equal(cvssV3VectorToSeverity("CVSS:3.1/AV:N"), "unknown");
      assert.equal(cvssV3VectorToSeverity("not a vector"), "unknown");
    });

    it("returns 'unknown' for missing required metrics", () => {
      assert.equal(cvssV3VectorToSeverity("CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H"), "unknown");
    });

    it("returns 'unknown' for invalid metric values", () => {
      assert.equal(cvssV3VectorToSeverity("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "unknown");
    });
  });

  describe("edge cases", () => {
    it("handles whitespace around vector", () => {
      const vector = "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ";
      assert.equal(cvssV3VectorToSeverity(vector), "critical");
    });

    it("handles zero impact (all None)", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
      assert.equal(cvssV3VectorToSeverity(vector), "unknown");
    });
  });
});

describe("cvssV3ToScore", () => {
  it("returns numeric score for valid vectors", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const score = cvssV3ToScore(vector);
    assert.ok(typeof score === "number");
    assert.equal(score, 9.8);
  });

  it("returns null for invalid vectors", () => {
    assert.equal(cvssV3ToScore(""), null);
    assert.equal(cvssV3ToScore("not-a-vector"), null);
    assert.equal(cvssV3ToScore("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"), null);
  });

  it("returns 0 for zero-impact vectors", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    assert.equal(cvssV3ToScore(vector), 0);
  });

  it("calculates correct score for known vector", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H";
    const score = cvssV3ToScore(vector);
    assert.ok(score != null);
    assert.ok(Math.abs(score - 6.5) < 0.2, `Expected ~6.5, got ${score}`);
  });

  it("handles scope changed vectors", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
    const score = cvssV3ToScore(vector);
    assert.ok(score != null);
    assert.ok(score >= 8.0, `Expected >= 8.0 for changed scope, got ${score}`);
  });
});

describe("scoreToSeverity", () => {
  it("maps scores to correct severity levels", () => {
    assert.equal(scoreToSeverity(10), "critical");
    assert.equal(scoreToSeverity(9.0), "critical");
    assert.equal(scoreToSeverity(8.5), "high");
    assert.equal(scoreToSeverity(7.0), "high");
    assert.equal(scoreToSeverity(5.5), "medium");
    assert.equal(scoreToSeverity(4.0), "medium");
    assert.equal(scoreToSeverity(2.0), "low");
    assert.equal(scoreToSeverity(0.1), "low");
    assert.equal(scoreToSeverity(0), "unknown");
  });
});

describe("parseCvssV3", () => {
  it("returns full parse result for valid vector", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const result = parseCvssV3(vector);
    assert.ok(result);
    assert.equal(result.vector, vector);
    assert.equal(result.score, 9.8);
    assert.equal(result.severity, "critical");
    assert.equal(result.metrics.attackVector, "N");
    assert.equal(result.metrics.attackComplexity, "L");
    assert.equal(result.metrics.privilegesRequired, "N");
    assert.equal(result.metrics.userInteraction, "N");
    assert.equal(result.metrics.scope, "U");
    assert.equal(result.metrics.confidentiality, "H");
    assert.equal(result.metrics.integrity, "H");
    assert.equal(result.metrics.availability, "H");
    assert.ok(result.attackVectorLabel === "Network");
    assert.ok(result.exploitabilityLabel.includes("remotely exploitable"));
    assert.ok(result.exploitabilityLabel.includes("no user interaction"));
    assert.ok(result.exploitabilityLabel.includes("no privileges required"));
  });

  it("returns null for invalid vector", () => {
    assert.equal(parseCvssV3(""), null);
    assert.equal(parseCvssV3("garbage"), null);
  });

  it("handles local attack vector", () => {
    const vector = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L";
    const result = parseCvssV3(vector);
    assert.ok(result);
    assert.equal(result.attackVectorLabel, "Local");
    assert.ok(result.exploitabilityLabel.includes("requires local access"));
  });

  it("handles physical attack vector", () => {
    const vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L";
    const result = parseCvssV3(vector);
    assert.ok(result);
    assert.equal(result.attackVectorLabel, "Physical");
    assert.ok(result.exploitabilityLabel.includes("requires physical access"));
  });

  it("handles required user interaction", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H";
    const result = parseCvssV3(vector);
    assert.ok(result);
    assert.ok(!result.exploitabilityLabel.includes("no user interaction"));
  });
});
