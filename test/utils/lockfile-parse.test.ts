import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parsePnpmPackageKey, getRegistryDisplayName } from "../../src/utils/lockfile";

describe("parsePnpmPackageKey", () => {
  describe("unscoped packages", () => {
    it("parses simple package key", () => {
      const result = parsePnpmPackageKey("/lodash/4.17.21");
      assert.deepEqual(result, { name: "lodash", version: "4.17.21" });
    });

    it("parses without leading slash", () => {
      const result = parsePnpmPackageKey("lodash/4.17.21");
      assert.deepEqual(result, { name: "lodash", version: "4.17.21" });
    });
  });

  describe("scoped packages", () => {
    it("parses scoped package key", () => {
      const result = parsePnpmPackageKey("/@types/node/20.10.0");
      assert.deepEqual(result, { name: "@types/node", version: "20.10.0" });
    });

    it("parses various scoped packages", () => {
      assert.deepEqual(
        parsePnpmPackageKey("/@babel/core/7.23.0"),
        { name: "@babel/core", version: "7.23.0" }
      );
      assert.deepEqual(
        parsePnpmPackageKey("/@vue/compiler-sfc/3.4.0"),
        { name: "@vue/compiler-sfc", version: "3.4.0" }
      );
    });
  });

  describe("peer dependency suffix", () => {
    it("strips peer dependency suffix from version", () => {
      const result = parsePnpmPackageKey("/react-dom/18.2.0(react@18.2.0)");
      assert.deepEqual(result, { name: "react-dom", version: "18.2.0" });
    });

    it("handles complex peer suffix", () => {
      const result = parsePnpmPackageKey("/@testing-library/react/14.0.0(@types/react@18.2.0)(react-dom@18.2.0)(react@18.2.0)");
      assert.deepEqual(result, { name: "@testing-library/react", version: "14.0.0" });
    });
  });

  describe("registry prefix", () => {
    it("handles registry host prefix", () => {
      const result = parsePnpmPackageKey("/registry.npmjs.org/lodash/4.17.21");
      assert.deepEqual(result, { name: "lodash", version: "4.17.21" });
    });

    it("handles custom registry prefix with port", () => {
      const result = parsePnpmPackageKey("/localhost:4873/lodash/4.17.21");
      assert.deepEqual(result, { name: "lodash", version: "4.17.21" });
    });
  });

  describe("invalid keys", () => {
    it("returns null for key with only one part", () => {
      assert.equal(parsePnpmPackageKey("/lodash"), null);
      assert.equal(parsePnpmPackageKey("lodash"), null);
    });

    it("returns null for empty key", () => {
      assert.equal(parsePnpmPackageKey(""), null);
      assert.equal(parsePnpmPackageKey("/"), null);
    });

    it("returns null for incomplete scoped package", () => {
      assert.equal(parsePnpmPackageKey("/@types"), null);
      assert.equal(parsePnpmPackageKey("/@types/node"), null); // missing version
    });
  });

  describe("v9 format (@ separator)", () => {
    it("parses v9 format unscoped package", () => {
      const result = parsePnpmPackageKey("lodash@4.17.21");
      assert.deepEqual(result, { name: "lodash", version: "4.17.21" });
    });

    it("parses v9 format scoped package", () => {
      const result = parsePnpmPackageKey("@types/node@20.10.0");
      assert.deepEqual(result, { name: "@types/node", version: "20.10.0" });
    });

    it("parses v9 format with peer suffix", () => {
      const result = parsePnpmPackageKey("react-dom@18.2.0(react@18.2.0)");
      assert.deepEqual(result, { name: "react-dom", version: "18.2.0" });
    });

    it("parses v9 format scoped package with peer suffix", () => {
      const result = parsePnpmPackageKey("@testing-library/react@14.0.0(@types/react@18.2.0)(react@18.2.0)");
      assert.deepEqual(result, { name: "@testing-library/react", version: "14.0.0" });
    });

    it("parses various v9 scoped packages", () => {
      assert.deepEqual(
        parsePnpmPackageKey("@babel/core@7.23.0"),
        { name: "@babel/core", version: "7.23.0" }
      );
      assert.deepEqual(
        parsePnpmPackageKey("@vue/compiler-sfc@3.4.0"),
        { name: "@vue/compiler-sfc", version: "3.4.0" }
      );
    });
  });
});

describe("getRegistryDisplayName", () => {
  it("returns npmjs for npmjs registry URL", () => {
    assert.equal(getRegistryDisplayName("https://registry.npmjs.org/"), "npmjs");
  });

  it("returns azure for Azure DevOps registry URL", () => {
    assert.equal(
      getRegistryDisplayName("https://pkgs.dev.azure.com/npm/registry/"),
      "azure",
    );
  });

  it("returns github for GitHub Packages registry URL", () => {
    assert.equal(
      getRegistryDisplayName("https://npm.pkg.github.com/"),
      "github",
    );
  });

  it("returns hostname for unknown registry URL", () => {
    assert.equal(
      getRegistryDisplayName("https://custom-registry.internal.com/"),
      "custom-registry.internal.com",
    );
  });

  it("returns raw string for unparseable URL", () => {
    assert.equal(getRegistryDisplayName("not-a-url"), "not-a-url");
  });

  it("maps yarn registry to npmjs", () => {
    assert.equal(getRegistryDisplayName("https://registry.yarnpkg.com/"), "npmjs");
  });
});

