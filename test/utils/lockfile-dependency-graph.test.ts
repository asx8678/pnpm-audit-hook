import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildDependencyGraph, traceDependencyChain, extractPackagesFromLockfile } from "../../src/utils/lockfile";

describe("buildDependencyGraph", () => {
  describe("direct vs transitive classification", () => {
    it("marks express as direct and qs as transitive", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { express: "4.18.0" },
          },
        },
        packages: {
          "express@4.18.0": {
            resolution: { integrity: "sha512-abc" },
            dependencies: { qs: "6.11.0" },
          },
          "qs@6.11.0": {
            resolution: { integrity: "sha512-def" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      assert.equal(graph.nodes.size, 2);

      const express = graph.nodes.get("express@4.18.0");
      assert.ok(express);
      assert.equal(express.isDirect, true);
      assert.equal(express.isDev, false);
      assert.deepEqual(express.dependencies, ["qs@6.11.0"]);

      const qs = graph.nodes.get("qs@6.11.0");
      assert.ok(qs);
      assert.equal(qs.isDirect, false);
      assert.equal(qs.isDev, false);

      // Reverse edge: qs should have express as a dependent
      const qsDependents = graph.dependents.get("qs@6.11.0");
      assert.ok(qsDependents);
      assert.ok(qsDependents.has("express@4.18.0"));
    });
  });

  describe("multi-level chains", () => {
    it("builds correct edges for a -> b -> c chain", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { a: "1.0.0" },
          },
        },
        packages: {
          "a@1.0.0": {
            resolution: { integrity: "sha512-a" },
            dependencies: { b: "1.0.0" },
          },
          "b@1.0.0": {
            resolution: { integrity: "sha512-b" },
            dependencies: { c: "1.0.0" },
          },
          "c@1.0.0": {
            resolution: { integrity: "sha512-c" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      assert.equal(graph.nodes.size, 3);

      // a is direct
      const a = graph.nodes.get("a@1.0.0");
      assert.ok(a);
      assert.equal(a.isDirect, true);
      assert.deepEqual(a.dependencies, ["b@1.0.0"]);

      // b is transitive
      const b = graph.nodes.get("b@1.0.0");
      assert.ok(b);
      assert.equal(b.isDirect, false);
      assert.deepEqual(b.dependencies, ["c@1.0.0"]);

      // c is transitive
      const c = graph.nodes.get("c@1.0.0");
      assert.ok(c);
      assert.equal(c.isDirect, false);
      assert.deepEqual(c.dependencies, []);

      // Reverse edges
      assert.ok(graph.dependents.get("b@1.0.0")?.has("a@1.0.0"));
      assert.ok(graph.dependents.get("c@1.0.0")?.has("b@1.0.0"));
      // a has no dependents
      assert.equal(graph.dependents.get("a@1.0.0")?.size, 0);
    });
  });

  describe("scoped packages", () => {
    it("handles @types/node as a dependency", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: {
              "@types/node": "20.0.0",
            },
          },
        },
        packages: {
          "@types/node@20.0.0": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      assert.equal(graph.nodes.size, 1);
      const node = graph.nodes.get("@types/node@20.0.0");
      assert.ok(node);
      assert.equal(node.name, "@types/node");
      assert.equal(node.version, "20.0.0");
      assert.equal(node.isDirect, true);

      assert.deepEqual(graph.byName.get("@types/node"), ["@types/node@20.0.0"]);
    });

    it("handles scoped packages as transitive deps", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { pkg: "1.0.0" },
          },
        },
        packages: {
          "pkg@1.0.0": {
            resolution: { integrity: "sha512-a" },
            dependencies: { "@scope/dep": "2.0.0" },
          },
          "@scope/dep@2.0.0": {
            resolution: { integrity: "sha512-b" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);
      const scoped = graph.nodes.get("@scope/dep@2.0.0");
      assert.ok(scoped);
      assert.equal(scoped.isDirect, false);
      assert.equal(scoped.name, "@scope/dep");
    });
  });

  describe("dev vs production deps", () => {
    it("marks dev-only dependencies with isDev: true", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { express: "4.18.0" },
            devDependencies: { vitest: "1.0.0" },
          },
        },
        packages: {
          "express@4.18.0": {
            resolution: { integrity: "sha512-a" },
          },
          "vitest@1.0.0": {
            resolution: { integrity: "sha512-b" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      const express = graph.nodes.get("express@4.18.0");
      assert.ok(express);
      assert.equal(express.isDirect, true);
      assert.equal(express.isDev, false);

      const vitest = graph.nodes.get("vitest@1.0.0");
      assert.ok(vitest);
      assert.equal(vitest.isDirect, true);
      assert.equal(vitest.isDev, true);
    });

    it("package in both deps and devDeps is NOT dev-only", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { lodash: "4.17.21" },
            devDependencies: { lodash: "4.17.21" },
          },
        },
        packages: {
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);
      const lodash = graph.nodes.get("lodash@4.17.21");
      assert.ok(lodash);
      assert.equal(lodash.isDirect, true);
      assert.equal(lodash.isDev, false);
    });

    it("package in optionalDeps and devDeps is NOT dev-only", () => {
      const lockfile = {
        importers: {
          ".": {
            optionalDependencies: { fsevents: "2.3.3" },
            devDependencies: { fsevents: "2.3.3" },
          },
        },
        packages: {
          "fsevents@2.3.3": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);
      const fsevents = graph.nodes.get("fsevents@2.3.3");
      assert.ok(fsevents);
      assert.equal(fsevents.isDirect, true);
      assert.equal(fsevents.isDev, false);
    });
  });

  describe("optional and peer deps", () => {
    it("includes optional dependencies as edges", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { chokidar: "3.5.0" },
          },
        },
        packages: {
          "chokidar@3.5.0": {
            resolution: { integrity: "sha512-a" },
            optionalDependencies: { fsevents: "2.3.3" },
          },
          "fsevents@2.3.3": {
            resolution: { integrity: "sha512-b" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      const chokidar = graph.nodes.get("chokidar@3.5.0");
      assert.ok(chokidar);
      assert.deepEqual(chokidar.dependencies, ["fsevents@2.3.3"]);

      const fsevents = graph.nodes.get("fsevents@2.3.3");
      assert.ok(fsevents);
      assert.equal(fsevents.isDirect, false);
      assert.ok(graph.dependents.get("fsevents@2.3.3")?.has("chokidar@3.5.0"));
    });

    it("includes peer dependencies as edges", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { "react-dom": "18.2.0" },
          },
        },
        packages: {
          "react-dom@18.2.0": {
            resolution: { integrity: "sha512-a" },
            peerDependencies: { react: "18.2.0" },
          },
          "react@18.2.0": {
            resolution: { integrity: "sha512-b" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      const reactDom = graph.nodes.get("react-dom@18.2.0");
      assert.ok(reactDom);
      assert.deepEqual(reactDom.dependencies, ["react@18.2.0"]);

      assert.ok(graph.dependents.get("react@18.2.0")?.has("react-dom@18.2.0"));
    });
  });

  describe("multiple versions of same package", () => {
    it("maps package name to multiple version keys in byName", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { app: "1.0.0" },
          },
        },
        packages: {
          "app@1.0.0": {
            resolution: { integrity: "sha512-a" },
            dependencies: {
              lodash: "4.17.20",
              "lodash-old": "4.17.21",
            },
          },
          "lodash@4.17.20": {
            resolution: { integrity: "sha512-b" },
          },
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-c" },
          },
          "lodash-old@4.17.21": {
            resolution: { integrity: "sha512-d" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      const lodashVersions = graph.byName.get("lodash");
      assert.ok(lodashVersions);
      assert.equal(lodashVersions.length, 2);
      assert.ok(lodashVersions.includes("lodash@4.17.20"));
      assert.ok(lodashVersions.includes("lodash@4.17.21"));

      // Both versions exist as nodes
      assert.ok(graph.nodes.has("lodash@4.17.20"));
      assert.ok(graph.nodes.has("lodash@4.17.21"));
    });
  });

  describe("empty lockfile", () => {
    it("returns an empty graph for an empty lockfile", () => {
      const graph = buildDependencyGraph({});

      assert.equal(graph.nodes.size, 0);
      assert.equal(graph.byName.size, 0);
      assert.equal(graph.dependents.size, 0);
      assert.equal(graph.directKeys.size, 0);
    });

    it("returns an empty graph for a lockfile with only packages key", () => {
      const graph = buildDependencyGraph({ packages: {} });

      assert.equal(graph.nodes.size, 0);
    });
  });

  describe("lockfile with no importers", () => {
    it("includes packages in graph but marks none as direct", () => {
      const lockfile = {
        packages: {
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "express@4.18.0": {
            resolution: { integrity: "sha512-def" },
            dependencies: { lodash: "4.17.21" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      assert.equal(graph.nodes.size, 2);
      assert.equal(graph.directKeys.size, 0);

      for (const [, node] of graph.nodes) {
        assert.equal(node.isDirect, false);
        assert.equal(node.isDev, false);
      }

      // Edges should still be built
      const express = graph.nodes.get("express@4.18.0");
      assert.ok(express);
      assert.deepEqual(express.dependencies, ["lodash@4.17.21"]);
    });
  });

  describe("workspace with multiple importers", () => {
    it("shared deps from multiple importers are marked direct", () => {
      const lockfile = {
        importers: {
          "packages/app-a": {
            dependencies: { lodash: "4.17.21", axios: "1.6.0" },
          },
          "packages/app-b": {
            dependencies: { lodash: "4.17.21", express: "4.18.0" },
          },
        },
        packages: {
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-a" },
          },
          "axios@1.6.0": {
            resolution: { integrity: "sha512-b" },
          },
          "express@4.18.0": {
            resolution: { integrity: "sha512-c" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      // lodash is direct because it's in both importers
      const lodash = graph.nodes.get("lodash@4.17.21");
      assert.ok(lodash);
      assert.equal(lodash.isDirect, true);

      // axios is direct from app-a
      const axios = graph.nodes.get("axios@1.6.0");
      assert.ok(axios);
      assert.equal(axios.isDirect, true);

      // express is direct from app-b
      const express = graph.nodes.get("express@4.18.0");
      assert.ok(express);
      assert.equal(express.isDirect, true);

      assert.equal(graph.directKeys.size, 3);
    });

    it("classifies dev deps correctly across multiple importers", () => {
      const lockfile = {
        importers: {
          "packages/app": {
            dependencies: { react: "18.2.0" },
            devDependencies: { vitest: "1.0.0" },
          },
          "packages/lib": {
            dependencies: { vitest: "1.0.0" },
          },
        },
        packages: {
          "react@18.2.0": {
            resolution: { integrity: "sha512-a" },
          },
          "vitest@1.0.0": {
            resolution: { integrity: "sha512-b" },
          },
        },
      };

      const graph = buildDependencyGraph(lockfile);

      // vitest is dev in app but prod in lib → NOT dev-only
      const vitest = graph.nodes.get("vitest@1.0.0");
      assert.ok(vitest);
      assert.equal(vitest.isDirect, true);
      assert.equal(vitest.isDev, false);

      const react = graph.nodes.get("react@18.2.0");
      assert.ok(react);
      assert.equal(react.isDirect, true);
      assert.equal(react.isDev, false);
    });
  });

  describe("backward compatibility", () => {
    it("extractPackagesFromLockfile still works after buildDependencyGraph exists", () => {
      const lockfile = {
        importers: {
          ".": {
            dependencies: { lodash: "4.17.21" },
          },
        },
        packages: {
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
        },
      };

      // Both functions work independently
      const extractResult = extractPackagesFromLockfile(lockfile);
      const graph = buildDependencyGraph(lockfile);

      assert.equal(extractResult.packages.length, 1);
      assert.equal(extractResult.packages[0]!.name, "lodash");

      assert.equal(graph.nodes.size, 1);
      assert.ok(graph.nodes.has("lodash@4.17.21"));
    });
  });
});

describe("traceDependencyChain", () => {
  it("returns [key] for a direct dependency", () => {
    const lockfile = {
      importers: { ".": { dependencies: { express: "4.18.0" } } },
      packages: {
        "express@4.18.0": { resolution: { integrity: "sha512-abc" } },
      },
    };
    const graph = buildDependencyGraph(lockfile);
    const result = traceDependencyChain(graph, "express@4.18.0");
    assert.deepEqual(result, ["express@4.18.0"]);
  });

  it("traces single-hop transitive dependency", () => {
    const lockfile = {
      importers: { ".": { dependencies: { express: "4.18.0" } } },
      packages: {
        "express@4.18.0": {
          resolution: { integrity: "sha512-abc" },
          dependencies: { qs: "6.11.0" },
        },
        "qs@6.11.0": { resolution: { integrity: "sha512-def" } },
      },
    };
    const graph = buildDependencyGraph(lockfile);
    const result = traceDependencyChain(graph, "qs@6.11.0");
    assert.deepEqual(result, ["express@4.18.0", "qs@6.11.0"]);
  });

  it("traces multi-hop transitive dependency", () => {
    const lockfile = {
      importers: { ".": { dependencies: { a: "1.0.0" } } },
      packages: {
        "a@1.0.0": {
          resolution: { integrity: "sha512-a" },
          dependencies: { b: "1.0.0" },
        },
        "b@1.0.0": {
          resolution: { integrity: "sha512-b" },
          dependencies: { c: "1.0.0" },
        },
        "c@1.0.0": { resolution: { integrity: "sha512-c" } },
      },
    };
    const graph = buildDependencyGraph(lockfile);
    const result = traceDependencyChain(graph, "c@1.0.0");
    assert.deepEqual(result, ["a@1.0.0", "b@1.0.0", "c@1.0.0"]);
  });

  it("finds shortest path in diamond dependency", () => {
    // a -> b -> d and a -> c -> d (both paths length 3)
    const lockfile = {
      importers: { ".": { dependencies: { a: "1.0.0" } } },
      packages: {
        "a@1.0.0": {
          resolution: { integrity: "sha512-a" },
          dependencies: { b: "1.0.0", c: "1.0.0" },
        },
        "b@1.0.0": {
          resolution: { integrity: "sha512-b" },
          dependencies: { d: "1.0.0" },
        },
        "c@1.0.0": {
          resolution: { integrity: "sha512-c" },
          dependencies: { d: "1.0.0" },
        },
        "d@1.0.0": { resolution: { integrity: "sha512-d" } },
      },
    };
    const graph = buildDependencyGraph(lockfile);
    const result = traceDependencyChain(graph, "d@1.0.0");
    assert.ok(result);
    // Both paths are length 3, either is fine
    assert.equal(result.length, 3);
    assert.equal(result[0], "a@1.0.0");
    assert.equal(result[2], "d@1.0.0");
  });

  it("finds shortest path with multiple direct paths", () => {
    // a@1.0.0 -> b@1.0.0 -> c@1.0.0 (depth 3)
    // d@1.0.0 -> c@1.0.0 (depth 2 — shorter!)
    const lockfile = {
      importers: {
        ".": { dependencies: { a: "1.0.0", d: "1.0.0" } },
      },
      packages: {
        "a@1.0.0": {
          resolution: { integrity: "sha512-a" },
          dependencies: { b: "1.0.0" },
        },
        "b@1.0.0": {
          resolution: { integrity: "sha512-b" },
          dependencies: { c: "1.0.0" },
        },
        "c@1.0.0": { resolution: { integrity: "sha512-c" } },
        "d@1.0.0": {
          resolution: { integrity: "sha512-d" },
          dependencies: { c: "1.0.0" },
        },
      },
    };
    const graph = buildDependencyGraph(lockfile);
    const result = traceDependencyChain(graph, "c@1.0.0");
    assert.ok(result);
    // Shortest path is d -> c (length 2)
    assert.deepEqual(result, ["d@1.0.0", "c@1.0.0"]);
  });

  it("returns null when target is not in graph", () => {
    const lockfile = {
      importers: { ".": { dependencies: { a: "1.0.0" } } },
      packages: {
        "a@1.0.0": { resolution: { integrity: "sha512-a" } },
      },
    };
    const graph = buildDependencyGraph(lockfile);
    const result = traceDependencyChain(graph, "nonexistent@9.9.9");
    assert.equal(result, null);
  });

  it("handles scoped packages correctly", () => {
    const lockfile = {
      importers: { ".": { dependencies: { "@scope/a": "1.0.0" } } },
      packages: {
        "@scope/a@1.0.0": {
          resolution: { integrity: "sha512-a" },
          dependencies: { "@scope/b": "2.0.0" },
        },
        "@scope/b@2.0.0": { resolution: { integrity: "sha512-b" } },
      },
    };
    const graph = buildDependencyGraph(lockfile);
    const result = traceDependencyChain(graph, "@scope/b@2.0.0");
    assert.deepEqual(result, ["@scope/a@1.0.0", "@scope/b@2.0.0"]);
  });
});
