import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parsePnpmPackageKey, extractPackagesFromLockfile } from "../../src/utils/lockfile";

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
});

describe("extractPackagesFromLockfile", () => {
  describe("basic extraction", () => {
    it("extracts packages from lockfile", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc123" },
          },
          "/express/4.18.2": {
            resolution: { integrity: "sha512-def456" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 2);
      
      const names = result.packages.map(p => p.name).sort();
      assert.deepEqual(names, ["express", "lodash"]);
    });

    it("extracts scoped packages", () => {
      const lockfile = {
        packages: {
          "/@types/node/20.10.0": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
      assert.equal(result.packages[0]!.name, "@types/node");
      assert.equal(result.packages[0]!.version, "20.10.0");
    });
  });

  describe("direct dependency detection", () => {
    it("marks direct dependencies", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: {
              lodash: "4.17.21",
            },
            devDependencies: {
              typescript: "5.3.0",
            },
          },
        },
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "/typescript/5.3.0": {
            resolution: { integrity: "sha512-def" },
          },
          "/semver/7.5.0": {
            resolution: { integrity: "sha512-ghi" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 3);

      const lodash = result.packages.find(p => p.name === "lodash");
      const typescript = result.packages.find(p => p.name === "typescript");
      const semver = result.packages.find(p => p.name === "semver");

      assert.equal(lodash?.direct, true);
      assert.equal(typescript?.direct, true);
      assert.equal(semver?.direct, undefined);
    });

    it("handles optionalDependencies", () => {
      const lockfile = {
        importers: {
          ".": {
            optionalDependencies: {
              fsevents: "2.3.3",
            },
          },
        },
        packages: {
          "/fsevents/2.3.3": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      const fsevents = result.packages.find(p => p.name === "fsevents");
      assert.equal(fsevents?.direct, true);
    });
  });

  describe("filtering non-registry packages", () => {
    it("excludes directory packages", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "file:../local-pkg": {
            resolution: { directory: "../local-pkg", type: "directory" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
      assert.equal(result.packages[0]!.name, "lodash");
    });

    it("excludes path-based packages", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "link:../sibling": {
            resolution: { path: "../sibling" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
    });

    it("includes http tarball packages", () => {
      const lockfile = {
        packages: {
          "/custom-pkg/1.0.0": {
            resolution: { tarball: "https://example.com/pkg.tgz" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
    });

    it("excludes file tarball packages", () => {
      const lockfile = {
        packages: {
          "/local-pkg/1.0.0": {
            resolution: { tarball: "file:./local.tgz" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 0);
    });
  });

  describe("edge cases", () => {
    it("handles empty lockfile", () => {
      const result = extractPackagesFromLockfile({});
      assert.deepEqual(result.packages, []);
    });

    it("handles missing packages key", () => {
      const result = extractPackagesFromLockfile({ importers: {} });
      assert.deepEqual(result.packages, []);
    });

    it("handles null/undefined lockfile", () => {
      const result = extractPackagesFromLockfile(null);
      assert.deepEqual(result.packages, []);

      const result2 = extractPackagesFromLockfile(undefined);
      assert.deepEqual(result2.packages, []);
    });

    it("handles peer suffix in importer versions", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: {
              "react-dom": "18.2.0(react@18.2.0)",
            },
          },
        },
        packages: {
          "/react-dom/18.2.0(react@18.2.0)": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      const reactDom = result.packages.find(p => p.name === "react-dom");
      assert.equal(reactDom?.version, "18.2.0");
      assert.equal(reactDom?.direct, true);
    });
  });
});
