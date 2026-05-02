import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { extractRegistryInfo } from "../../src/utils/lockfile";

describe("extractRegistryInfo", () => {
  describe("tarball-based registry extraction", () => {
    it("extracts npmjs from npmjs tarball", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: {
              tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.get("lodash@4.17.21"), "npmjs");
    });

    it("extracts azure from Azure DevOps tarball", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: {
              tarball: "https://pkgs.dev.azure.com/myorg/_packaging/myregistry/npm/registry/lodash/-/lodash-4.17.21.tgz",
            },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.get("lodash@4.17.21"), "azure");
    });

    it("extracts github from GitHub Packages tarball", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: {
              tarball: "https://npm.pkg.github.com/download/@scope/lodash/4.17.21/hash.tgz",
            },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.get("lodash@4.17.21"), "github");
    });

    it("extracts custom hostname for unknown registry", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: {
              tarball: "https://custom-registry.internal.com/lodash/-/lodash-4.17.21.tgz",
            },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.get("lodash@4.17.21"), "custom-registry.internal.com");
    });

    it("maps yarn registry to npmjs", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: {
              tarball: "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz",
            },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.get("lodash@4.17.21"), "npmjs");
    });
  });

  describe("default registry fallback", () => {
    it("uses default registry for integrity-only packages", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc123" },
          },
        },
      };

      const result = extractRegistryInfo(lockfile, "https://registry.npmjs.org/");
      assert.equal(result.get("lodash@4.17.21"), "npmjs");
    });

    it("returns empty map when no default registry and no tarball", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc123" },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.size, 0);
    });

    it("uses default registry with custom hostname", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc123" },
          },
        },
      };

      const result = extractRegistryInfo(lockfile, "https://custom-registry.internal.com/");
      assert.equal(result.get("lodash@4.17.21"), "custom-registry.internal.com");
    });
  });

  describe("edge cases", () => {
    it("skips file tarballs (local packages)", () => {
      const lockfile = {
        packages: {
          "/local-pkg/1.0.0": {
            resolution: { tarball: "file:./local.tgz" },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.size, 0);
    });

    it("skips packages with no resolution", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {},
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.size, 0);
    });

    it("handles empty lockfile", () => {
      const result = extractRegistryInfo({});
      assert.equal(result.size, 0);
    });

    it("handles missing packages key", () => {
      const result = extractRegistryInfo({ importers: {} });
      assert.equal(result.size, 0);
    });
  });

  describe("mixed registries", () => {
    it("identifies packages from different registries", () => {
      const lockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: {
              tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            },
          },
          "/@company/utils/1.0.0": {
            resolution: {
              tarball: "https://pkgs.dev.azure.com/myorg/_packaging/myregistry/npm/registry/@company/utils/-/utils-1.0.0.tgz",
            },
          },
          "/express/4.18.2": {
            resolution: { integrity: "sha512-def456" },
          },
        },
      };

      const result = extractRegistryInfo(lockfile, "https://registry.npmjs.org/");
      assert.equal(result.get("lodash@4.17.21"), "npmjs");
      assert.equal(result.get("@company/utils@1.0.0"), "azure");
      assert.equal(result.get("express@4.18.2"), "npmjs"); // uses default
    });
  });

  describe("scoped packages with custom registries", () => {
    it("extracts registry from scoped package tarball", () => {
      const lockfile = {
        packages: {
          "/@company/pkg/2.0.0": {
            resolution: {
              tarball: "https://pkgs.dev.azure.com/myorg/_packaging/myregistry/npm/registry/@company/pkg/-/pkg-2.0.0.tgz",
            },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.get("@company/pkg@2.0.0"), "azure");
    });
  });

  describe("v9 format", () => {
    it("works with v9 format package keys", () => {
      const lockfile = {
        packages: {
          "lodash@4.17.21": {
            resolution: {
              tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            },
          },
          "@types/node@20.10.0": {
            resolution: {
              tarball: "https://registry.npmjs.org/@types/node/-/node-20.10.0.tgz",
            },
          },
        },
      };

      const result = extractRegistryInfo(lockfile);
      assert.equal(result.get("lodash@4.17.21"), "npmjs");
      assert.equal(result.get("@types/node@20.10.0"), "npmjs");
    });
  });
});

