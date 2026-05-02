import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { extractPackagesFromLockfile } from "../../src/utils/lockfile";

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

    it("handles empty packages object", () => {
      const lockfile = {
        packages: {},
        importers: {
          ".": {
            dependencies: { lodash: "4.17.21" },
          },
        },
      };
      const result = extractPackagesFromLockfile(lockfile);
      assert.deepEqual(result.packages, []);
    });

    it("handles missing importers", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };
      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
      assert.equal(result.packages[0]!.name, "lodash");
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
    });
  });

  describe("filtering non-registry packages (git, local)", () => {
    it("excludes git packages without integrity", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "github.com/user/repo/abc123": {
            resolution: {},
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
      assert.equal(result.packages[0]!.name, "lodash");
    });

    it("excludes local file references", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "file:packages/local-pkg": {
            resolution: { directory: "packages/local-pkg", type: "directory" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
      assert.equal(result.packages[0]!.name, "lodash");
    });

    it("excludes link packages", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "link:../other-workspace": {
            resolution: { path: "../other-workspace" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 1);
    });
  });

  describe("v9 format extraction", () => {
    it("extracts v9 format packages with integrity", () => {
      const lockfile = {
        packages: {
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "@types/node@20.10.0": {
            resolution: { integrity: "sha512-def" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 2);

      const names = result.packages.map(p => p.name).sort();
      assert.deepEqual(names, ["@types/node", "lodash"]);
    });

    it("handles v9 format with peer suffix in packages", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: {
              "react-dom": "18.2.0(react@18.2.0)",
            },
          },
        },
        packages: {
          "react-dom@18.2.0(react@18.2.0)": {
            resolution: { integrity: "sha512-abc" },
          },
          "react@18.2.0": {
            resolution: { integrity: "sha512-def" },
          },
        },
      };

      const result = extractPackagesFromLockfile(lockfile);
      assert.equal(result.packages.length, 2);

      const reactDom = result.packages.find(p => p.name === "react-dom");
      assert.equal(reactDom?.version, "18.2.0");
    });
  });
});

