import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { cvssV3VectorToSeverity } from "../../src/utils/cvss";

describe("cvssV3VectorToSeverity", () => {
  describe("valid CVSS 3.1 vectors", () => {
    it("returns 'critical' for score >= 9.0", () => {
      // CVSS 3.1 critical: Network/Low/None/Unchanged/High/High/High
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      assert.equal(cvssV3VectorToSeverity(vector), "critical");
    });

    it("returns 'high' for score >= 7.0 and < 9.0", () => {
      // CVSS 3.1 high: Network/Low/None/Required/Unchanged/High/High/High
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
      assert.equal(cvssV3VectorToSeverity(vector), "high");
    });

    it("returns 'medium' for score >= 4.0 and < 7.0", () => {
      // CVSS 3.1 medium: Network/High/Low/Required/Unchanged/Low/Low/Low
      const vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L";
      assert.equal(cvssV3VectorToSeverity(vector), "medium");
    });

    it("returns 'low' for score > 0 and < 4.0", () => {
      // CVSS 3.1 low: Physical/High/High/Required/Unchanged/None/None/Low
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
      // Changed scope affects the score calculation
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
      // Missing AC
      assert.equal(cvssV3VectorToSeverity("CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H"), "unknown");
    });

    it("returns 'unknown' for invalid metric values", () => {
      // Invalid AV value 'X'
      assert.equal(cvssV3VectorToSeverity("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "unknown");
    });
  });

  describe("edge cases", () => {
    it("handles whitespace around vector", () => {
      const vector = "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ";
      assert.equal(cvssV3VectorToSeverity(vector), "critical");
    });

    it("handles zero impact (all None)", () => {
      // When C/I/A are all None, impact is 0 and score should be unknown
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
      assert.equal(cvssV3VectorToSeverity(vector), "unknown");
    });
  });
});
