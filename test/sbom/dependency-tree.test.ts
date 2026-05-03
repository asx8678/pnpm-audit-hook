/**
 * SBOM Dependency Tree Visualization tests.
 *
 * Tests for building trees from CycloneDX/SPDX SBOM documents and
 * pnpm lockfiles, plus ASCII/JSON rendering correctness.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import {
  buildTreeFromSbom,
  buildTreeFromLockfile,
  renderTree,
  renderTreeJson,
} from "../../src/sbom/dependency-tree";
import type {
  CycloneDXBom,
  CycloneDXComponent,
  CycloneDXDependency,
  CycloneDXVulnerability,
  SPDXDocument,
  SPDXPackage,
  SPDXRelationship,
  TreeNode,
} from "../../src/sbom/types";

// ============================================================================
// Test Fixtures: CycloneDX
// ============================================================================

function makeCycloneDXBom(
  components: CycloneDXComponent[],
  dependencies?: CycloneDXDependency[],
  vulnerabilities?: CycloneDXVulnerability[],
  metadataComponent?: CycloneDXComponent,
): CycloneDXBom {
  const bom: CycloneDXBom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:test-tree-serial",
    version: 1,
    metadata: {
      timestamp: "2025-05-01T00:00:00.000Z",
      tools: [
        { vendor: "test", name: "test-tool", version: "1.0.0" },
      ],
      component: metadataComponent,
    },
    components,
  };
  if (dependencies) bom.dependencies = dependencies;
  if (vulnerabilities) bom.vulnerabilities = vulnerabilities;
  return bom;
}

function cdxComponent(name: string, version: string): CycloneDXComponent {
  return {
    type: "library",
    "bom-ref": `pkg:npm/${encodeURIComponent(name)}@${version}`,
    name,
    version,
    purl: `pkg:npm/${encodeURIComponent(name)}@${version}`,
  };
}

function cdxDependency(
  ref: string,
  dependsOn: string[],
): CycloneDXDependency {
  return { ref, dependsOn };
}

function cdxVulnerability(
  id: string,
  severity: string,
  affectsRef: string,
): CycloneDXVulnerability {
  return {
    id,
    ratings: [{ severity }],
    affects: [{ ref: affectsRef }],
  };
}

// ============================================================================
// Test Fixtures: SPDX
// ============================================================================

function makeSpdxDoc(
  packages: SPDXPackage[],
  relationships: SPDXRelationship[],
): SPDXDocument {
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "test-project",
    documentNamespace: "https://spdx.org/spdxdocs/test",
    creationInfo: {
      created: "2025-05-01T00:00:00Z",
      creators: ["Tool: test"],
    },
    documentDescribes: ["SPDXRef-DOCUMENT"],
    packages,
    relationships,
  };
}

function spdxPackage(
  name: string,
  version: string,
  spdxId?: string,
): SPDXPackage {
  const id = spdxId ?? `SPDXRef-Package-${name.replace(/[^a-zA-Z0-9]/g, "-")}`;
  return {
    SPDXID: id,
    name,
    versionInfo: version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: `pkg:npm/${encodeURIComponent(name)}@${version}`,
      },
    ],
  };
}

function spdxRelationship(
  fromId: string,
  type: string,
  toId: string,
): SPDXRelationship {
  return {
    SPDXElementID: fromId,
    RelationshipType: type,
    RelatedSPDXElement: toId,
  };
}

// ============================================================================
// CycloneDX Tree Building
// ============================================================================

describe("buildTreeFromSbom - CycloneDX", () => {
  it("should build a simple two-level tree", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("my-project", "1.0.0"),
        cdxComponent("express", "4.18.2"),
        cdxComponent("lodash", "4.17.21"),
      ],
      [
        cdxDependency("pkg:npm/my-project@1.0.0", [
          "pkg:npm/express@4.18.2",
          "pkg:npm/lodash@4.17.21",
        ]),
      ],
      undefined,
      cdxComponent("my-project", "1.0.0"),
    );

    const tree = buildTreeFromSbom(bom);

    assert.equal(tree.name, "my-project");
    assert.equal(tree.version, "1.0.0");
    assert.equal(tree.children.length, 2);
    assert.equal(tree.children[0]?.name, "express");
    assert.equal(tree.children[1]?.name, "lodash");
    assert.equal(tree.depth, 0);
  });

  it("should build a three-level tree", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("express", "4.18.2"),
        cdxComponent("body-parser", "1.20.0"),
        cdxComponent("qs", "6.11.0"),
      ],
      [
        cdxDependency("pkg:npm/express@4.18.2", [
          "pkg:npm/body-parser@1.20.0",
        ]),
        cdxDependency("pkg:npm/body-parser@1.20.0", ["pkg:npm/qs@6.11.0"]),
      ],
    );

    const tree = buildTreeFromSbom(bom);

    assert.equal(tree.name, "express");
    assert.equal(tree.children.length, 1);
    assert.equal(tree.children[0]?.name, "body-parser");
    assert.equal(tree.children[0]?.children.length, 1);
    assert.equal(tree.children[0]?.children[0]?.name, "qs");
    assert.equal(tree.children[0]?.children[0]?.depth, 2);
  });

  it("should handle vulnerability annotations", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("express", "4.18.2"),
        cdxComponent("debug", "2.6.9"),
      ],
      [
        cdxDependency("pkg:npm/express@4.18.2", ["pkg:npm/debug@2.6.9"]),
      ],
      [
        cdxVulnerability(
          "CVE-2017-16137",
          "low",
          "pkg:npm/debug@2.6.9",
        ),
      ],
    );

    const tree = buildTreeFromSbom(bom, { showVulnerabilities: true });

    assert.equal(tree.children[0]?.name, "debug");
    assert.ok(tree.children[0]?.vulnerabilities);
    assert.equal(tree.children[0]?.vulnerabilities?.length, 1);
    assert.equal(tree.children[0]?.vulnerabilities?.[0]?.id, "CVE-2017-16137");
    assert.equal(tree.children[0]?.vulnerabilities?.[0]?.severity, "low");
  });

  it("should respect maxDepth option", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("a", "1.0.0"),
        cdxComponent("b", "1.0.0"),
        cdxComponent("c", "1.0.0"),
        cdxComponent("d", "1.0.0"),
      ],
      [
        cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/b@1.0.0"]),
        cdxDependency("pkg:npm/b@1.0.0", ["pkg:npm/c@1.0.0"]),
        cdxDependency("pkg:npm/c@1.0.0", ["pkg:npm/d@1.0.0"]),
      ],
    );

    const tree = buildTreeFromSbom(bom, { maxDepth: 2 });

    assert.equal(tree.name, "a");
    assert.equal(tree.children.length, 1);
    assert.equal(tree.children[0]?.name, "b");
    // b -> c should exist (depth 2 <= maxDepth 2)
    assert.equal(tree.children[0]?.children.length, 1);
    assert.equal(tree.children[0]?.children[0]?.name, "c");
    // c -> d should NOT exist (depth 3 > maxDepth 2)
    assert.equal(tree.children[0]?.children[0]?.children.length, 0);
  });

  it("should hide versions when showVersions is false", () => {
    const bom = makeCycloneDXBom(
      [cdxComponent("express", "4.18.2")],
      undefined,
    );

    const tree = buildTreeFromSbom(bom, { showVersions: false });

    assert.equal(tree.version, "");
  });

  it("should handle empty SBOM (no components)", () => {
    const bom = makeCycloneDXBom([]);

    const tree = buildTreeFromSbom(bom);

    assert.equal(tree.name, "project");
    assert.equal(tree.children.length, 0);
  });

  it("should detect cycles and not loop infinitely", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("a", "1.0.0"),
        cdxComponent("b", "1.0.0"),
      ],
      [
        cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/b@1.0.0"]),
        cdxDependency("pkg:npm/b@1.0.0", ["pkg:npm/a@1.0.0"]),
      ],
    );

    const tree = buildTreeFromSbom(bom);

    // Should not throw or hang
    assert.equal(tree.name, "a");
    assert.equal(tree.children.length, 1);
    assert.equal(tree.children[0]?.name, "b");
    // b -> a cycle should be shown as a node but with no children
    assert.equal(tree.children[0]?.children.length, 1);
    assert.equal(tree.children[0]?.children[0]?.name, "a");
    assert.equal(tree.children[0]?.children[0]?.children.length, 0);
  });

  it("should extract purl info for scoped packages", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("@types/node", "20.10.0"),
        cdxComponent("express", "4.18.2"),
      ],
      [
        cdxDependency("pkg:npm/express@4.18.2", [
          "pkg:npm/@types/node@20.10.0",
        ]),
      ],
    );

    const tree = buildTreeFromSbom(bom);

    const scoped = tree.children[0];
    assert.equal(scoped?.name, "node");
    assert.equal(scoped?.group, "@types");
  });
});

// ============================================================================
// SPDX Tree Building
// ============================================================================

describe("buildTreeFromSbom - SPDX", () => {
  it("should build a tree from SPDX relationships", () => {
    const docPkg = spdxPackage("my-project", "1.0.0", "SPDXRef-DOCUMENT");
    const expressPkg = spdxPackage("express", "4.18.2");
    const lodashPkg = spdxPackage("lodash", "4.17.21");
    const qsPkg = spdxPackage("qs", "6.11.0");

    const doc = makeSpdxDoc(
      [docPkg, expressPkg, lodashPkg, qsPkg],
      [
        spdxRelationship("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Package-express"),
        spdxRelationship("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Package-lodash"),
        spdxRelationship("SPDXRef-Package-express", "DEPENDS_ON", "SPDXRef-Package-qs"),
      ],
    );

    const tree = buildTreeFromSbom(doc);

    assert.equal(tree.name, "my-project");
    // express and lodash are top-level (DESCRIBES targets)
    assert.equal(tree.children.length, 2);
  });

  it("should handle SPDX with no relationships", () => {
    const doc = makeSpdxDoc(
      [spdxPackage("lodash", "4.17.21")],
      [],
    );

    const tree = buildTreeFromSbom(doc);

    assert.equal(tree.name, "test-project");
    assert.equal(tree.children.length, 0);
  });

  it("should handle scoped packages in SPDX", () => {
    const docPkg = spdxPackage("my-project", "1.0.0", "SPDXRef-DOCUMENT");
    const scopedPkg = spdxPackage("@scope/package", "1.0.0");
    // spdxPackage generates SPDXID from name: @scope/package -> -scope-package
    const scopedSpdxId = scopedPkg.SPDXID;

    const doc = makeSpdxDoc(
      [docPkg, scopedPkg],
      [
        spdxRelationship("SPDXRef-DOCUMENT", "DESCRIBES", scopedSpdxId),
      ],
    );

    const tree = buildTreeFromSbom(doc);

    assert.equal(tree.children.length, 1);
    assert.equal(tree.children[0]?.name, "package");
    assert.equal(tree.children[0]?.group, "@scope");
  });
});

// ============================================================================
// Lockfile Tree Building
// ============================================================================

describe("buildTreeFromLockfile", () => {
  const fixturesDir = path.join(__dirname, "..", "fixtures", "lockfiles");

  it("should build tree from pnpm v9 lockfile", () => {
    const lockfilePath = path.join(fixturesDir, "pnpm-v9.yaml");
    const tree = buildTreeFromLockfile(lockfilePath);

    // Root should be from package.json (project name)
    assert.ok(tree.name);
    assert.ok(tree.children.length > 0);
    assert.equal(tree.depth, 0);

    // Check direct deps: lodash, axios, typescript (dev)
    const depNames = tree.children.map((c) => c.name);
    assert.ok(depNames.includes("lodash"));
    assert.ok(depNames.includes("axios"));
  });

  it("should build nested tree from lockfile", () => {
    const lockfilePath = path.join(fixturesDir, "pnpm-v9.yaml");
    const tree = buildTreeFromLockfile(lockfilePath);

    // Find axios node
    const axiosNode = tree.children.find((c) => c.name === "axios");
    assert.ok(axiosNode);

    // axios depends on follow-redirects and form-data
    const childNames = axiosNode.children.map((c) => c.name);
    assert.ok(childNames.includes("follow-redirects"));
    assert.ok(childNames.includes("form-data"));
  });

  it("should respect maxDepth from lockfile", () => {
    const lockfilePath = path.join(fixturesDir, "pnpm-v9.yaml");
    const tree = buildTreeFromLockfile(lockfilePath, { maxDepth: 1 });

    // Direct deps should be present but their children should not
    const axiosNode = tree.children.find((c) => c.name === "axios");
    assert.ok(axiosNode);
    assert.equal(axiosNode.children.length, 0);
  });

  it("should hide versions from lockfile tree when showVersions is false", () => {
    const lockfilePath = path.join(fixturesDir, "pnpm-v9.yaml");
    const tree = buildTreeFromLockfile(lockfilePath, { showVersions: false });

    for (const child of tree.children) {
      assert.equal(child.version, "");
    }
  });
});

// ============================================================================
// ASCII Rendering
// ============================================================================

describe("renderTree - ASCII", () => {
  it("should render root node correctly", () => {
    const tree: TreeNode = {
      name: "my-project",
      version: "1.0.0",
      children: [],
      depth: 0,
    };

    const output = renderTree(tree);
    assert.equal(output, "my-project@1.0.0");
  });

  it("should render tree with box-drawing characters", () => {
    const tree: TreeNode = {
      name: "my-project",
      version: "1.0.0",
      children: [
        {
          name: "express",
          version: "4.18.2",
          children: [],
          depth: 1,
        },
        {
          name: "lodash",
          version: "4.17.21",
          children: [],
          depth: 1,
        },
      ],
      depth: 0,
    };

    const output = renderTree(tree);
    const lines = output.split("\n");

    assert.equal(lines[0], "my-project@1.0.0");
    assert.ok(lines[1]?.includes("├── express@4.18.2"));
    assert.ok(lines[2]?.includes("└── lodash@4.17.21"));
  });

  it("should render nested tree with correct indentation", () => {
    const tree: TreeNode = {
      name: "my-project",
      version: "1.0.0",
      children: [
        {
          name: "express",
          version: "4.18.2",
          children: [
            {
              name: "body-parser",
              version: "1.20.0",
              children: [
                {
                  name: "qs",
                  version: "6.11.0",
                  children: [],
                  depth: 3,
                },
              ],
              depth: 2,
            },
          ],
          depth: 1,
        },
      ],
      depth: 0,
    };

    const output = renderTree(tree);
    const lines = output.split("\n");

    assert.equal(lines[0], "my-project@1.0.0");
    assert.equal(lines[1], "└── express@4.18.2");
    assert.equal(lines[2], "    └── body-parser@1.20.0");
    assert.equal(lines[3], "        └── qs@6.11.0");
  });

  it("should render vulnerability markers", () => {
    const tree: TreeNode = {
      name: "my-project",
      version: "1.0.0",
      children: [
        {
          name: "debug",
          version: "2.6.9",
          vulnerabilities: [
            { id: "CVE-2017-16137", severity: "low" },
          ],
          children: [],
          depth: 1,
        },
      ],
      depth: 0,
    };

    const output = renderTree(tree);
    assert.ok(output.includes("⚠️ CVE-2017-16137 (low)"));
  });

  it("should render mixed last/non-last children with correct connectors", () => {
    const tree: TreeNode = {
      name: "root",
      version: "1.0.0",
      children: [
        { name: "a", version: "1.0.0", children: [], depth: 1 },
        { name: "b", version: "1.0.0", children: [], depth: 1 },
        { name: "c", version: "1.0.0", children: [], depth: 1 },
      ],
      depth: 0,
    };

    const output = renderTree(tree);
    const lines = output.split("\n");

    assert.ok(lines[1]?.startsWith("├── a@1.0.0"));
    assert.ok(lines[2]?.startsWith("├── b@1.0.0"));
    assert.ok(lines[3]?.startsWith("└── c@1.0.0"));
  });

  it("should handle a deep tree (5+ levels)", () => {
    const tree: TreeNode = {
      name: "root",
      version: "1.0.0",
      depth: 0,
      children: [
        {
          name: "a",
          version: "1.0.0",
          depth: 1,
          children: [
            {
              name: "b",
              version: "1.0.0",
              depth: 2,
              children: [
                {
                  name: "c",
                  version: "1.0.0",
                  depth: 3,
                  children: [
                    {
                      name: "d",
                      version: "1.0.0",
                      depth: 4,
                      children: [
                        {
                          name: "e",
                          version: "1.0.0",
                          depth: 5,
                          children: [],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    };

    const output = renderTree(tree);
    const lines = output.split("\n");

    assert.equal(lines[0], "root@1.0.0");
    assert.ok(lines[1]?.includes("a@1.0.0"));
    assert.ok(lines[2]?.includes("b@1.0.0"));
    assert.ok(lines[3]?.includes("c@1.0.0"));
    assert.ok(lines[4]?.includes("d@1.0.0"));
    assert.ok(lines[5]?.includes("e@1.0.0"));

    // Check indentation increases properly
    assert.ok(lines[5]!.indexOf("e@1.0.0") > lines[4]!.indexOf("d@1.0.0"));
  });

  it("should hide versions when showVersions is false", () => {
    const tree: TreeNode = {
      name: "root",
      version: "1.0.0",
      children: [
        { name: "dep", version: "2.0.0", children: [], depth: 1 },
      ],
      depth: 0,
    };

    const output = renderTree(tree, { showVersions: false });
    const lines = output.split("\n");

    assert.equal(lines[0], "root");
    assert.ok(lines[1]?.includes("dep"));
    assert.ok(!lines[1]?.includes("@"));
  });

  it("should handle empty children list", () => {
    const tree: TreeNode = {
      name: "solo",
      version: "1.0.0",
      children: [],
      depth: 0,
    };

    const output = renderTree(tree);
    assert.equal(output, "solo@1.0.0");
  });
});

// ============================================================================
// JSON Rendering
// ============================================================================

describe("renderTreeJson", () => {
  it("should render a simple tree as JSON", () => {
    const tree: TreeNode = {
      name: "my-project",
      version: "1.0.0",
      purl: "pkg:npm/my-project@1.0.0",
      children: [
        {
          name: "express",
          version: "4.18.2",
          purl: "pkg:npm/express@4.18.2",
          children: [],
          depth: 1,
        },
      ],
      depth: 0,
    };

    const json = renderTreeJson(tree);

    assert.equal(json.name, "my-project");
    assert.equal(json.version, "1.0.0");
    assert.equal(json.purl, "pkg:npm/my-project@1.0.0");
    assert.ok(json.children);
    assert.equal(json.children!.length, 1);
    assert.equal(json.children![0]!.name, "express");
    assert.equal(json.children![0]!.version, "4.18.2");
  });

  it("should include vulnerability info in JSON output", () => {
    const tree: TreeNode = {
      name: "debug",
      version: "2.6.9",
      vulnerabilities: [{ id: "CVE-2017-16137", severity: "low" }],
      children: [],
      depth: 0,
    };

    const json = renderTreeJson(tree);

    assert.ok(json.vulnerabilities);
    assert.equal(json.vulnerabilities!.length, 1);
    assert.equal(json.vulnerabilities![0]!.id, "CVE-2017-16137");
    assert.equal(json.vulnerabilities![0]!.severity, "low");
  });

  it("should omit versions when showVersions is false", () => {
    const tree: TreeNode = {
      name: "root",
      version: "1.0.0",
      children: [],
      depth: 0,
    };

    const json = renderTreeJson(tree, { showVersions: false });

    assert.equal(json.version, undefined);
  });

  it("should omit vulnerabilities when showVulnerabilities is false", () => {
    const tree: TreeNode = {
      name: "debug",
      version: "2.6.9",
      vulnerabilities: [{ id: "CVE-2017-16137", severity: "low" }],
      children: [],
      depth: 0,
    };

    const json = renderTreeJson(tree, { showVulnerabilities: false });

    assert.equal(json.vulnerabilities, undefined);
  });

  it("should include group for scoped packages", () => {
    const tree: TreeNode = {
      name: "node",
      version: "20.10.0",
      group: "@types",
      children: [],
      depth: 0,
    };

    const json = renderTreeJson(tree);

    assert.equal(json.group, "@types");
  });

  it("should produce valid JSON (can be serialized and re-parsed)", () => {
    const tree: TreeNode = {
      name: "root",
      version: "1.0.0",
      purl: "pkg:npm/root@1.0.0",
      vulnerabilities: [{ id: "CVE-123", severity: "high" }],
      children: [
        {
          name: "dep-a",
          version: "1.0.0",
          children: [],
          depth: 1,
        },
        {
          name: "dep-b",
          version: "2.0.0",
          children: [
            {
              name: "dep-c",
              version: "3.0.0",
              children: [],
              depth: 3,
            },
          ],
          depth: 2,
        },
      ],
      depth: 0,
    };

    const json = renderTreeJson(tree);
    const serialized = JSON.stringify(json);
    const parsed = JSON.parse(serialized);

    assert.equal(parsed.name, "root");
    assert.equal(parsed.children.length, 2);
    assert.equal(parsed.children[1].children[0].name, "dep-c");
  });
});

// ============================================================================
// Format Detection
// ============================================================================

describe("buildTreeFromSbom - format detection", () => {
  it("should throw on unrecognized format", () => {
    assert.throws(
      () => buildTreeFromSbom({ randomField: true }),
      /Unrecognized SBOM format/,
    );
  });

  it("should detect CycloneDX by bomFormat", () => {
    const bom = makeCycloneDXBom([]);
    const tree = buildTreeFromSbom(bom);
    assert.ok(tree);
    assert.equal(tree.name, "project");
  });

  it("should detect SPDX by spdxVersion", () => {
    const doc = makeSpdxDoc([], []);
    const tree = buildTreeFromSbom(doc);
    assert.ok(tree);
  });
});

// ============================================================================
// Performance
// ============================================================================

describe("performance", () => {
  it("should handle large dependency trees (100+ packages) within 1s", () => {
    const components: CycloneDXComponent[] = [];
    const deps: CycloneDXDependency[] = [];

    // Build a tree: root -> 10 groups of 10 packages each, each with 10 subdeps
    for (let g = 0; g < 10; g++) {
      const groupName = `group-${g}`;
      components.push(cdxComponent(groupName, "1.0.0"));
      const childRefs: string[] = [];
      for (let i = 0; i < 10; i++) {
        const name = `pkg-${g}-${i}`;
        components.push(cdxComponent(name, "1.0.0"));
        childRefs.push(`pkg:npm/${name}@1.0.0`);

        const subRefs: string[] = [];
        for (let j = 0; j < 10; j++) {
          const subName = `sub-${g}-${i}-${j}`;
          components.push(cdxComponent(subName, "1.0.0"));
          subRefs.push(`pkg:npm/${subName}@1.0.0`);
        }
        deps.push(cdxDependency(`pkg:npm/${name}@1.0.0`, subRefs));
      }
      deps.push(cdxDependency(`pkg:npm/${groupName}@1.0.0`, childRefs));
    }

    const bom = makeCycloneDXBom(components, deps);

    const start = Date.now();
    const tree = buildTreeFromSbom(bom);
    const output = renderTree(tree);
    const elapsed = Date.now() - start;

    assert.ok(tree);
    assert.ok(output);
    assert.ok(elapsed < 2000, `Took ${elapsed}ms, expected < 2000ms`);
    assert.equal(tree.children.length, 10);
  });

  it("should handle 100+ direct dependencies from lockfile", () => {
    // Create a synthetic lockfile-like YAML string for performance testing
    const lines: string[] = ['lockfileVersion: \'9.0\'', '', 'importers:', '  .:', '    dependencies:'];
    for (let i = 0; i < 120; i++) {
      lines.push(`      pkg-${i}:`);
      lines.push(`        specifier: ^1.0.0`);
      lines.push(`        version: 1.0.0`);
    }
    lines.push('', 'packages:');
    for (let i = 0; i < 120; i++) {
      lines.push(`  /pkg-${i}@1.0.0:`);
      lines.push(`    resolution: {integrity: sha512-test${i}}`);
      lines.push('    dev: false');
      lines.push('');
    }

    // Write temp file
    const fs = require("node:fs");
    const os = require("node:os");
    const tmpFile = path.join(os.tmpdir(), `perf-test-lockfile-${Date.now()}.yaml`);
    fs.writeFileSync(tmpFile, lines.join("\n"), "utf-8");

    try {
      const start = Date.now();
      const tree = buildTreeFromLockfile(tmpFile);
      const output = renderTree(tree);
      const elapsed = Date.now() - start;

      assert.equal(tree.children.length, 120);
      assert.ok(output);
      assert.ok(elapsed < 2000, `Took ${elapsed}ms, expected < 2000ms`);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });
});

// ============================================================================
// Edge Cases
// ============================================================================

describe("edge cases", () => {
  it("should handle tree with missing dependency references gracefully", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("a", "1.0.0"),
        // b is referenced but not defined
      ],
      [
        cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/b@1.0.0"]),
      ],
    );

    const tree = buildTreeFromSbom(bom);

    assert.equal(tree.name, "a");
    // Missing ref should just be skipped
    assert.equal(tree.children.length, 0);
  });

  it("should handle root with purl group (scoped)", () => {
    const bom = makeCycloneDXBom(
      [cdxComponent("@my-scope/my-app", "1.0.0")],
      undefined,
      undefined,
      cdxComponent("@my-scope/my-app", "1.0.0"),
    );

    const tree = buildTreeFromSbom(bom);

    assert.equal(tree.group, "@my-scope");
    assert.equal(tree.name, "my-app");
  });

  it("should produce deterministic output", () => {
    const bom = makeCycloneDXBom(
      [
        cdxComponent("a", "1.0.0"),
        cdxComponent("b", "1.0.0"),
      ],
      [cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/b@1.0.0"])],
    );

    const tree1 = buildTreeFromSbom(bom);
    const tree2 = buildTreeFromSbom(bom);
    const output1 = renderTree(tree1);
    const output2 = renderTree(tree2);

    assert.equal(output1, output2);
  });
});
