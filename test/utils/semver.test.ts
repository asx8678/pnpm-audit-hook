import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { satisfies, isVersionAffectedByOsvSemverRange, npmPurl } from "../../src/utils/semver";

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
    it("returns false for invalid version", () => {
      assert.equal(satisfies("not-a-version", "^1.0.0"), false);
      assert.equal(satisfies("", "^1.0.0"), false);
      assert.equal(satisfies("abc", "1.x"), false);
    });

    it("returns false for invalid range", () => {
      assert.equal(satisfies("1.2.3", "invalid-range"), false);
      assert.equal(satisfies("1.2.3", ">>>bad"), false);
    });

    it("treats empty range as matching any version (semver behavior)", () => {
      // Empty range in semver means "any version"
      assert.equal(satisfies("1.2.3", ""), true);
    });
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
