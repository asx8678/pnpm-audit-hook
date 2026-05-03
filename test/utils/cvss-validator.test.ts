import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CvssValidator,
  detectCvssVersion,
  validateCvssVector,
  parseCvssVector,
  isCvssVectorValid,
  getCvssVersion,
} from "../../src/utils/cvss-validator";

describe("CvssValidator", () => {
  const validator = new CvssValidator();

  describe("version detection", () => {
    it("detects CVSS:2.0 prefix", () => {
      const vector = "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C";
      assert.equal(detectCvssVersion(vector), "2.0");
    });

    it("detects CVSS:3.0 prefix", () => {
      const vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      assert.equal(detectCvssVersion(vector), "3.0");
    });

    it("detects CVSS:3.1 prefix", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      assert.equal(detectCvssVersion(vector), "3.1");
    });

    it("detects CVSS:4.0 prefix", () => {
      const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
      assert.equal(detectCvssVersion(vector), "4.0");
    });

    it("detects legacy CVSS v2 format (no prefix)", () => {
      const vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
      assert.equal(detectCvssVersion(vector), "2.0");
    });

    it("returns undefined for unknown format", () => {
      assert.equal(detectCvssVersion("invalid"), undefined);
      assert.equal(detectCvssVersion("CVSS:5.0/AV:N"), undefined);
    });
  });

  describe("CVSS v3.1 validation", () => {
    it("validates correct CVSS 3.1 vector", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.equal(result.version, "3.1");
      assert.equal(result.score, 9.8);
      assert.equal(result.severity, "critical");
      assert.deepEqual(result.errors, []);
    });

    it("validates high severity vector", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.equal(result.score, 8.8);
      assert.equal(result.severity, "high");
    });

    it("validates medium severity vector", () => {
      const vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.ok(result.score! >= 4.0 && result.score! < 7.0);
      assert.equal(result.severity, "medium");
    });

    it("validates low severity vector", () => {
      const vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.ok(result.score! > 0 && result.score! < 4.0);
      assert.equal(result.severity, "low");
    });

    it("detects missing required metrics", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H";
      const result = validator.validate(vector);
      assert.equal(result.isValid, false);
      assert.ok(result.errors.some((e) => e.includes("Missing required metric: A")));
    });

    it("detects invalid metric values", () => {
      const vector = "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const result = validator.validate(vector);
      assert.equal(result.isValid, false);
      assert.ok(result.errors.some((e) => e.includes("Invalid value for AV")));
    });

    it("detects unexpected metrics", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y";
      const result = validator.validate(vector);
      assert.equal(result.isValid, false);
      assert.ok(result.errors.some((e) => e.includes("Unexpected metric")));
    });
  });

  describe("CVSS v3.0 validation", () => {
    it("validates CVSS 3.0 vector", () => {
      const vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.equal(result.version, "3.0");
      assert.equal(result.score, 9.8);
    });
  });

  describe("CVSS v2.0 validation", () => {
    it("validates correct CVSS 2.0 vector", () => {
      const vector = "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.equal(result.version, "2.0");
      assert.ok(typeof result.score === "number");
    });

    it("validates legacy CVSS v2 format", () => {
      const vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.equal(result.version, "2.0");
    });

    it("detects missing v2 required metrics", () => {
      const vector = "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C";
      const result = validator.validate(vector);
      assert.equal(result.isValid, false);
      assert.ok(result.errors.some((e) => e.includes("Missing required metric: A")));
    });
  });

  describe("CVSS v4.0 validation", () => {
    it("validates correct CVSS 4.0 vector", () => {
      const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.equal(result.version, "4.0");
      assert.ok(typeof result.score === "number");
    });

    it("detects missing v4 required metrics", () => {
      const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N";
      const result = validator.validate(vector);
      assert.equal(result.isValid, false);
      assert.ok(result.errors.some((e) => e.includes("Missing required metric: SA")));
    });
  });

  describe("input validation", () => {
    it("rejects empty string", () => {
      const result = validator.validate("");
      assert.equal(result.isValid, false);
      assert.ok(result.errors.length > 0);
    });

    it("rejects null input", () => {
      const result = validator.validate(null as unknown as string);
      assert.equal(result.isValid, false);
      assert.ok(result.errors.some((e) => e.includes("non-empty string")));
    });

    it("rejects whitespace-only input", () => {
      const result = validator.validate("   ");
      assert.equal(result.isValid, false);
    });
  });

  describe("parseVector", () => {
    it("returns full vector info for valid vector", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const info = validator.parseVector(vector);
      assert.equal(info.version, "3.1");
      assert.equal(info.score, 9.8);
      assert.equal(info.severity, "critical");
      assert.equal(info.isValid, true);
      assert.equal(info.vector, vector);
      assert.equal(info.metrics.attackVector, "N");
      assert.equal(info.metrics.attackComplexity, "L");
      assert.equal(info.metrics.privilegesRequired, "N");
      assert.equal(info.metrics.userInteraction, "N");
      assert.equal(info.metrics.scope, "U");
      assert.equal(info.metrics.confidentiality, "H");
      assert.equal(info.metrics.integrity, "H");
      assert.equal(info.metrics.availability, "H");
      assert.equal(info.validationErrors, undefined);
    });

    it("includes validation errors for invalid vector", () => {
      const vector = "CVSS:3.1/AV:N/AC:L";
      const info = validator.parseVector(vector);
      assert.equal(info.isValid, false);
      assert.ok(info.validationErrors && info.validationErrors.length > 0);
    });
  });

  describe("isValid", () => {
    it("returns true for valid vector", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      assert.equal(validator.isValid(vector), true);
    });

    it("returns false for invalid vector", () => {
      assert.equal(validator.isValid("invalid"), false);
      assert.equal(validator.isValid(""), false);
    });
  });

  describe("getVersion", () => {
    it("returns version for valid vector", () => {
      assert.equal(
        validator.getVersion("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "3.1",
      );
    });

    it("returns undefined for invalid vector", () => {
      assert.equal(validator.getVersion("invalid"), undefined);
    });
  });

  describe("getMetricLabel", () => {
    it("returns human-readable label for AV metric", () => {
      assert.equal(validator.getMetricLabel("AV", "N"), "Network");
      assert.equal(validator.getMetricLabel("AV", "A"), "Adjacent");
      assert.equal(validator.getMetricLabel("AV", "L"), "Local");
      assert.equal(validator.getMetricLabel("AV", "P"), "Physical");
    });

    it("returns human-readable label for AC metric", () => {
      assert.equal(validator.getMetricLabel("AC", "L"), "Low");
      assert.equal(validator.getMetricLabel("AC", "H"), "High");
    });

    it("returns raw value for unknown metric", () => {
      assert.equal(validator.getMetricLabel("XX", "Y"), "Y");
    });
  });

  describe("scope changed vectors", () => {
    it("validates CVSS 3.1 with scope changed", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
      const result = validator.validate(vector);
      assert.equal(result.isValid, true);
      assert.ok(result.score! >= 8.0);
    });
  });
});

describe("convenience functions", () => {
  describe("validateCvssVector", () => {
    it("validates vector using default validator", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const result = validateCvssVector(vector);
      assert.equal(result.isValid, true);
      assert.equal(result.score, 9.8);
    });
  });

  describe("parseCvssVector", () => {
    it("parses vector using default validator", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const info = parseCvssVector(vector);
      assert.equal(info.isValid, true);
      assert.equal(info.metrics.attackVector, "N");
    });
  });

  describe("isCvssVectorValid", () => {
    it("returns true for valid vector", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      assert.equal(isCvssVectorValid(vector), true);
    });

    it("returns false for invalid vector", () => {
      assert.equal(isCvssVectorValid("invalid"), false);
    });
  });

  describe("getCvssVersion", () => {
    it("returns version for valid vector", () => {
      assert.equal(
        getCvssVersion("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "3.1",
      );
    });

    it("returns undefined for invalid vector", () => {
      assert.equal(getCvssVersion("invalid"), undefined);
    });
  });
});

describe("edge cases", () => {
  const validator = new CvssValidator();

  it("handles vectors with extra whitespace", () => {
    const vector = "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ";
    const result = validator.validate(vector);
    assert.equal(result.isValid, true);
  });

  it("handles zero-impact vectors", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    const result = validator.validate(vector);
    assert.equal(result.isValid, true);
    assert.equal(result.score, 0);
  });

  it("handles vectors with many optional metrics", () => {
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:U/RC:C";
    const result = validator.validate(vector);
    // Should detect unexpected metrics
    assert.equal(result.isValid, false);
    assert.ok(result.errors.some((e) => e.includes("Unexpected metric")));
  });
});
