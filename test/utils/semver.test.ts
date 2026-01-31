import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { satisfies, satisfiesStrict, isVersionAffectedByOsvSemverRange, npmPurl } from "../../src/utils/semver";

describe("satisfies", () => {
  describe("valid versions and ranges", () => {
    it("returns true when version satisfies range", () => {
      assert.equal(satisfies("1.2.3", "^1.0.0"), true);
      assert.equal(satisfies("1.2.3", ">=1.0.0"), true);
      assert.equal(satisfies("1.2.3", "1.x"), true);
      assert.equal(satisfies("2.0.0", ">=2.0.0"), true);
    });

    it("returns false when version does not satisfy range", () => {
      assert.equal(satisfies("2.0.0", "^1.0.0"), false);
      assert.equal(satisfies("0.9.0", ">=1.0.0"), false);
      assert.equal(satisfies("1.2.3", "<1.0.0"), false);
    });

    it("handles exact version matches", () => {
      assert.equal(satisfies("1.2.3", "1.2.3"), true);
      assert.equal(satisfies("1.2.3", "1.2.4"), false);
    });

    it("handles prerelease versions", () => {
      assert.equal(satisfies("1.0.0-alpha.1", ">=1.0.0-alpha.0"), true);
      assert.equal(satisfies("1.0.0-beta", ">=1.0.0-alpha"), true);
    });
  });

  describe("invalid inputs", () => {
    it("returns true for invalid version (fail-closed)", () => {
      assert.equal(satisfies("not-a-version", "^1.0.0"), true);
      assert.equal(satisfies("", "^1.0.0"), true);
      assert.equal(satisfies("abc", "1.x"), true);
    });

    it("returns false for malformed range (semver behavior)", () => {
      // Malformed ranges return false in semver (range not satisfied)
      assert.equal(satisfies("1.2.3", ">>>bad"), false);
      assert.equal(satisfies("1.2.3", "invalid-range"), false);
      assert.equal(satisfies("1.2.3", "[1.0.0, 2.0.0)"), false); // bracket notation not supported
    });

    it("documents fail-closed behavior for exception-throwing ranges", () => {
      // The satisfies function wraps semver.satisfies in a try/catch.
      // If semver.satisfies throws an exception, we return true (fail-closed).
      // This ensures unknown/problematic ranges are treated as potentially affected.
      //
      // Note: The semver library handles most malformed ranges gracefully
      // (returning false rather than throwing). Finding a range that actually
      // throws is difficult. This test documents the intended behavior:
      // - Invalid versions: return true (fail-closed)
      // - Malformed ranges: semver returns false (no exception)
      // - Exception-throwing ranges: would return true (fail-closed)
      //
      // Testing a complex but valid range to verify normal operation:
      const result = satisfies("1.2.3", ">=1.0.0 <2.0.0 || >=3.0.0 <4.0.0");
      assert.equal(result, true);
    });

    it("treats empty range as matching any version (semver behavior)", () => {
      // Empty range in semver means "any version"
      assert.equal(satisfies("1.2.3", ""), true);
    });
  });

  describe("GitHub Advisory comma-separated ranges", () => {
    it("normalizes comma-separated ranges to space-separated", () => {
      // GitHub returns ">= 1.0.0, < 1.2.6" but semver expects ">=1.0.0 <1.2.6"
      assert.equal(satisfies("1.1.0", ">= 1.0.0, < 1.2.6"), true);
      assert.equal(satisfies("1.2.6", ">= 1.0.0, < 1.2.6"), false);
      assert.equal(satisfies("0.9.0", ">= 1.0.0, < 1.2.6"), false);
    });

    it("handles multiple commas in range", () => {
      // Multiple conditions separated by commas
      assert.equal(satisfies("1.5.0", ">= 1.0.0, < 2.0.0, >= 1.4.0"), true);
      assert.equal(satisfies("1.3.0", ">= 1.0.0, < 2.0.0, >= 1.4.0"), false);
    });

    it("handles commas with varying whitespace", () => {
      assert.equal(satisfies("1.1.0", ">=1.0.0,<2.0.0"), true);
      assert.equal(satisfies("1.1.0", ">=1.0.0,  <2.0.0"), true);
      assert.equal(satisfies("1.1.0", ">=1.0.0 , <2.0.0"), true);
    });
  });

  describe("prerelease handling", () => {
    it("handles prerelease versions with includePrerelease option", () => {
      // With includePrerelease: true, prereleases should match
      assert.equal(satisfies("1.0.0-alpha.1", ">=1.0.0-alpha.0 <1.0.0"), true);
      assert.equal(satisfies("2.0.0-beta.1", ">=2.0.0-alpha"), true);
      assert.equal(satisfies("1.0.0-rc.1", "^1.0.0-alpha"), true);
    });

    it("compares prerelease identifiers correctly", () => {
      assert.equal(satisfies("1.0.0-alpha", ">=1.0.0-alpha"), true);
      assert.equal(satisfies("1.0.0-alpha.1", ">1.0.0-alpha"), true);
      assert.equal(satisfies("1.0.0-beta", ">1.0.0-alpha"), true);
    });
  });
});

describe("satisfiesStrict", () => {
  it("returns true when version satisfies range", () => {
    assert.equal(satisfiesStrict("1.2.3", "^1.0.0"), true);
  });

  it("returns false for invalid versions", () => {
    assert.equal(satisfiesStrict("not-a-version", "^1.0.0"), false);
    assert.equal(satisfiesStrict("", "^1.0.0"), false);
  });

  it("returns false for malformed ranges", () => {
    assert.equal(satisfiesStrict("1.2.3", ">>>bad"), false);
  });
});

describe("isVersionAffectedByOsvSemverRange", () => {
  describe("introduced and fixed events", () => {
    it("returns true when version is in affected range", () => {
      const events = [
        { introduced: "1.0.0" },
        { fixed: "1.5.0" },
      ];
      assert.equal(isVersionAffectedByOsvSemverRange("1.2.3", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("1.0.0", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("1.4.9", events), true);
    });

    it("returns false when version is at or after fixed version", () => {
      const events = [
        { introduced: "1.0.0" },
        { fixed: "1.5.0" },
      ];
      assert.equal(isVersionAffectedByOsvSemverRange("1.5.0", events), false);
      assert.equal(isVersionAffectedByOsvSemverRange("2.0.0", events), false);
    });

    it("returns false when version is before introduced", () => {
      const events = [
        { introduced: "1.0.0" },
        { fixed: "1.5.0" },
      ];
      assert.equal(isVersionAffectedByOsvSemverRange("0.9.9", events), false);
    });
  });

  describe("introduced with no fix (still affected)", () => {
    it("returns true when only introduced with no fix", () => {
      const events = [{ introduced: "1.0.0" }];
      assert.equal(isVersionAffectedByOsvSemverRange("1.0.0", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("99.0.0", events), true);
    });
  });

  describe("last_affected events", () => {
    it("returns true when version is at or before last_affected", () => {
      const events = [
        { introduced: "1.0.0" },
        { last_affected: "1.5.0" },
      ];
      assert.equal(isVersionAffectedByOsvSemverRange("1.5.0", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("1.4.0", events), true);
    });

    it("returns false when version is after last_affected", () => {
      const events = [
        { introduced: "1.0.0" },
        { last_affected: "1.5.0" },
      ];
      assert.equal(isVersionAffectedByOsvSemverRange("1.5.1", events), false);
    });
  });

  describe("multiple ranges", () => {
    it("handles multiple introduced/fixed pairs", () => {
      const events = [
        { introduced: "1.0.0" },
        { fixed: "1.5.0" },
        { introduced: "2.0.0" },
        { fixed: "2.3.0" },
      ];
      // First range
      assert.equal(isVersionAffectedByOsvSemverRange("1.2.0", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("1.6.0", events), false);
      // Second range
      assert.equal(isVersionAffectedByOsvSemverRange("2.1.0", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("2.5.0", events), false);
    });
  });

  describe("special introduced value '0'", () => {
    it("normalizes '0' to '0.0.0'", () => {
      const events = [
        { introduced: "0" },
        { fixed: "1.0.0" },
      ];
      assert.equal(isVersionAffectedByOsvSemverRange("0.5.0", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("0.0.1", events), true);
      assert.equal(isVersionAffectedByOsvSemverRange("1.0.0", events), false);
    });
  });

  describe("invalid versions", () => {
    it("returns false for invalid version", () => {
      const events = [{ introduced: "1.0.0" }];
      assert.equal(isVersionAffectedByOsvSemverRange("invalid", events), false);
      assert.equal(isVersionAffectedByOsvSemverRange("", events), false);
    });
  });
});

describe("npmPurl", () => {
  describe("unscoped packages", () => {
    it("generates purl without version", () => {
      assert.equal(npmPurl("lodash"), "pkg:npm/lodash");
    });

    it("generates purl with version", () => {
      assert.equal(npmPurl("lodash", "4.17.21"), "pkg:npm/lodash@4.17.21");
    });
  });

  describe("scoped packages", () => {
    it("generates purl without version", () => {
      assert.equal(npmPurl("@types/node"), "pkg:npm/%40types/node");
    });

    it("generates purl with version", () => {
      assert.equal(npmPurl("@types/node", "20.10.0"), "pkg:npm/%40types/node@20.10.0");
    });

    it("handles various scoped packages", () => {
      assert.equal(npmPurl("@babel/core", "7.23.0"), "pkg:npm/%40babel/core@7.23.0");
      assert.equal(npmPurl("@vue/compiler-sfc"), "pkg:npm/%40vue/compiler-sfc");
    });
  });

  describe("special characters", () => {
    it("encodes special characters in version", () => {
      assert.equal(npmPurl("pkg", "1.0.0+build"), "pkg:npm/pkg@1.0.0%2Bbuild");
    });
  });
});
