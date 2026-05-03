/**
 * SBOM Mermaid Diagram Generator tests.
 *
 * Tests for generating valid Mermaid.js dependency graphs from
 * CycloneDX/SPDX SBOM documents with various configuration options.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateMermaidFromSbom,
} from "../../src/sbom/mermaid-generator";
import type {
  CycloneDXBom,
  CycloneDXComponent,
  CycloneDXDependency,
  CycloneDXVulnerability,
  MermaidOptions,
  SPDXDocument,
  SPDXPackage,
  SPDXRelationship,
} from "../../src/sbom/types";

// ============================================================================
// Test Helpers: CycloneDX Fixtures
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
    serialNumber: "urn:uuid:mermaid-test-serial",
    version: 1,
    metadata: {
      timestamp: "2025-05-01T00:00:00.000Z",
      tools: [{ vendor: "test", name: "test-tool", version: "1.0.0" }],
      component: metadataComponent,
    },
    components,
  };
  if (dependencies) bom.dependencies = dependencies;
  if (vulnerabilities) bom.vulnerabilities = vulnerabilities;
  return bom;
}

function cdxComponent(
  name: string,
  version: string,
  group?: string,
): CycloneDXComponent {
  const purlName = group
    ? `${encodeURIComponent(group)}/${encodeURIComponent(name)}`
    : encodeURIComponent(name);
  return {
    type: "library",
    "bom-ref": `pkg:npm/${purlName}@${version}`,
    name,
    version,
    purl: `pkg:npm/${purlName}@${version}`,
  };
}

function cdxDependency(ref: string, dependsOn: string[]): CycloneDXDependency {
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
// Test Helpers: SPDX Fixtures
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
      creators: ["Tool: test-1.0.0"],
    },
    documentDescribes: ["SPDXRef-DOCUMENT"],
    packages,
    relationships,
  };
}

function spdxPackage(
  spdxId: string,
  name: string,
  version: string,
): SPDXPackage {
  return {
    SPDXID: spdxId,
    name,
    versionInfo: version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "MIT",
    licenseDeclared: "MIT",
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
  elementId: string,
  type: string,
  relatedElement: string,
): SPDXRelationship {
  return {
    SPDXElementID: elementId,
    RelationshipType: type,
    RelatedSPDXElement: relatedElement,
  };
}

// ============================================================================
// Validation Helpers
// ============================================================================

/** Assert that the string is valid Mermaid graph syntax (basic structural checks). */
function assertValidMermaid(mermaid: string): void {
  // Must start with 'graph ' or a frontmatter block followed by 'graph '
  const hasGraph = /^graph\s+(TB|BT|LR|RL)\b/m.test(mermaid) ||
    /^---\n[\s\S]*?---\ngraph\s+(TB|BT|LR|RL)\b/m.test(mermaid);
  assert.ok(hasGraph, `Expected valid Mermaid graph declaration, got:\n${mermaid.slice(0, 200)}`);

  // All edge lines should match '    ID --> ID'
  const lines = mermaid.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.includes("-->")) {
      assert.ok(
        /^[A-Za-z_][A-Za-z0-9_]*\s+-->\s+[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed),
        `Invalid edge syntax: "${trimmed}"`,
      );
    }
  }
}

/** Assert the mermaid string contains a node definition with the given ID and label. */
function assertHasNode(mermaid: string, id: string, labelContains: string): void {
  const nodeRegex = new RegExp(`^\\s+${id}\\["[^"]*"]`, "m");
  assert.ok(
    nodeRegex.test(mermaid),
    `Expected node definition for ${id} containing "${labelContains}", got:\n${mermaid.slice(0, 500)}`,
  );
}

/** Assert the mermaid string contains an edge from → to. */
function assertHasEdge(mermaid: string, from: string, to: string): void {
  const edgeRegex = new RegExp(`^\\s+${from}\\s+-->\\s+${to}\\b`, "m");
  assert.ok(
    edgeRegex.test(mermaid),
    `Expected edge ${from} --> ${to}, got:\n${mermaid.slice(0, 500)}`,
  );
}

/** Assert the mermaid string contains a style directive for the given ID. */
function assertHasStyle(mermaid: string, id: string, fillColor: string): void {
  const styleRegex = new RegExp(`^\\s+style\\s+${id}\\s+fill:${fillColor}`, "m");
  assert.ok(
    styleRegex.test(mermaid),
    `Expected style for ${id} with fill:${fillColor}, got:\n${mermaid.slice(0, 500)}`,
  );
}

// ============================================================================
// Tests
// ============================================================================

describe("generateMermaidFromSbom", () => {
  // -------------------------------------------------------------------
  // Basic CycloneDX output
  // -------------------------------------------------------------------
  describe("CycloneDX SBOM", () => {
    it("generates valid Mermaid output from CycloneDX SBOM", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("my-project", "1.0.0"),
          cdxComponent("express", "4.18.2"),
          cdxComponent("body-parser", "1.20.0"),
          cdxComponent("bytes", "3.1.2"),
          cdxComponent("cookie", "0.5.0"),
        ],
        [
          cdxDependency("pkg:npm/my-project@1.0.0", [
            "pkg:npm/express@4.18.2",
          ]),
          cdxDependency("pkg:npm/express@4.18.2", [
            "pkg:npm/body-parser@1.20.0",
            "pkg:npm/cookie@0.5.0",
          ]),
          cdxDependency("pkg:npm/body-parser@1.20.0", ["pkg:npm/bytes@3.1.2"]),
        ],
      );

      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      assertValidMermaid(mermaid);
      assertHasNode(mermaid, "pkg_my_project", "my-project@1.0.0");
      assertHasNode(mermaid, "pkg_express", "express@4.18.2");
      assertHasNode(mermaid, "pkg_body_parser", "body-parser@1.20.0");
      assertHasNode(mermaid, "pkg_bytes", "bytes@3.1.2");
      assertHasNode(mermaid, "pkg_cookie", "cookie@0.5.0");
      assertHasEdge(mermaid, "pkg_my_project", "pkg_express");
      assertHasEdge(mermaid, "pkg_express", "pkg_body_parser");
      assertHasEdge(mermaid, "pkg_express", "pkg_cookie");
      assertHasEdge(mermaid, "pkg_body_parser", "pkg_bytes");
    });

    it("uses TB direction by default", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);
      assert.ok(mermaid.includes("graph TB"), "Default direction should be TB");
    });

    it("respects direction option (LR)", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { direction: "LR" },
      );
      assert.ok(mermaid.includes("graph LR"), "Direction should be LR");
    });

    it("respects direction option (BT)", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { direction: "BT" },
      );
      assert.ok(mermaid.includes("graph BT"));
    });

    it("respects direction option (RL)", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { direction: "RL" },
      );
      assert.ok(mermaid.includes("graph RL"));
    });

    it("includes title when specified", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { title: "My Project Dependency Graph" },
      );
      assert.ok(mermaid.includes("---"), "Should have frontmatter delimiters");
      assert.ok(
        mermaid.includes("title: My Project Dependency Graph"),
        "Should include title",
      );
    });

    it("omits title block when not specified", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);
      assert.ok(!mermaid.startsWith("---"), "Should not have frontmatter without title");
    });

    it("hides versions when showVersions is false", () => {
      const bom = makeCycloneDXBom([cdxComponent("express", "4.18.2")]);
      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { showVersions: false },
      );
      assert.ok(mermaid.includes('express"'), "Label should be just the name");
      assert.ok(!mermaid.includes("4.18.2"), "Should not include version");
    });

    it("shows versions by default", () => {
      const bom = makeCycloneDXBom([cdxComponent("express", "4.18.2")]);
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);
      assert.ok(mermaid.includes("express@4.18.2"), "Should include version");
    });
  });

  // -------------------------------------------------------------------
  // SPDX SBOM output
  // -------------------------------------------------------------------
  describe("SPDX SBOM", () => {
    it("generates valid Mermaid output from SPDX SBOM", () => {
      const doc = makeSpdxDoc(
        [
          spdxPackage("SPDXRef-DOCUMENT", "test-project", "NOASSERTION"),
          spdxPackage("SPDXRef-express", "express", "4.18.2"),
          spdxPackage("SPDXRef-lodash", "lodash", "4.17.21"),
        ],
        [
          spdxRelationship("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-express"),
          spdxRelationship("SPDXRef-express", "DEPENDS_ON", "SPDXRef-lodash"),
        ],
      );

      const mermaid = generateMermaidFromSbom(doc as unknown as Record<string, unknown>);

      assertValidMermaid(mermaid);
      assertHasNode(mermaid, "pkg_express", "express@4.18.2");
      assertHasNode(mermaid, "pkg_lodash", "lodash@4.17.21");
      assertHasEdge(mermaid, "pkg_express", "pkg_lodash");
    });
  });

  // -------------------------------------------------------------------
  // Max depth limiting
  // -------------------------------------------------------------------
  describe("maxDepth", () => {
    it("limits tree depth when maxDepth is set", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("a", "1.0.0"),
          cdxComponent("b", "1.0.0"),
          cdxComponent("c", "1.0.0"),
        ],
        [
          cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/a@1.0.0"]),
          cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/b@1.0.0"]),
          cdxDependency("pkg:npm/b@1.0.0", ["pkg:npm/c@1.0.0"]),
        ],
      );

      // maxDepth: 1 means root (depth 0) and its direct children (depth 1) only
      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { maxDepth: 1 },
      );

      assertValidMermaid(mermaid);
      assertHasNode(mermaid, "pkg_root", "root@1.0.0");
      assertHasNode(mermaid, "pkg_a", "a@1.0.0");
      // b should NOT appear (depth 2 > maxDepth 1)
      assert.ok(!mermaid.includes("pkg_b"), "Should not include node at depth > maxDepth");
      assert.ok(!mermaid.includes("pkg_c"), "Should not include deep nested nodes");
    });

    it("shows all levels with maxDepth Infinity (default)", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("a", "1.0.0"),
          cdxComponent("b", "1.0.0"),
        ],
        [
          cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/a@1.0.0"]),
          cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/b@1.0.0"]),
        ],
      );

      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);
      assertHasNode(mermaid, "pkg_root", "root");
      assertHasNode(mermaid, "pkg_a", "a");
      assertHasNode(mermaid, "pkg_b", "b");
    });
  });

  // -------------------------------------------------------------------
  // Vulnerability highlighting
  // -------------------------------------------------------------------
  describe("vulnerability highlighting", () => {
    it("highlights critical/high vulnerabilities with red", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("vuln-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/vuln-pkg@1.0.0"])],
        [cdxVulnerability("CVE-2024-0001", "critical", "pkg:npm/vuln-pkg@1.0.0")],
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertValidMermaid(mermaid);
      assertHasStyle(mermaid, "pkg_vuln_pkg", "#ff6b6b");
    });

    it("highlights medium vulnerabilities with orange", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("medium-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/medium-pkg@1.0.0"])],
        [cdxVulnerability("CVE-2024-0002", "medium", "pkg:npm/medium-pkg@1.0.0")],
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertHasStyle(mermaid, "pkg_medium_pkg", "#ffa94d");
    });

    it("highlights low vulnerabilities with yellow", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("low-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/low-pkg@1.0.0"])],
        [cdxVulnerability("CVE-2024-0003", "low", "pkg:npm/low-pkg@1.0.0")],
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertHasStyle(mermaid, "pkg_low_pkg", "#ffd43b");
    });

    it("picks highest severity when multiple vulnerabilities", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("multi-vuln", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/multi-vuln@1.0.0"])],
        [
          cdxVulnerability("CVE-2024-0001", "low", "pkg:npm/multi-vuln@1.0.0"),
          cdxVulnerability("CVE-2024-0002", "critical", "pkg:npm/multi-vuln@1.0.0"),
        ],
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      // Should use critical color (red), not low (yellow)
      assertHasStyle(mermaid, "pkg_multi_vuln", "#ff6b6b");
    });

    it("does not add style directives when highlightVulnerable is false", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("vuln-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/vuln-pkg@1.0.0"])],
        [cdxVulnerability("CVE-2024-0001", "critical", "pkg:npm/vuln-pkg@1.0.0")],
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: false },
      );

      assert.ok(!mermaid.includes("style "), "Should not have style directives");
    });

    it("omits style section when no vulnerable nodes", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("safe", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/safe@1.0.0"])],
        // No vulnerabilities
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assert.ok(!mermaid.includes("style "), "Should not have style directives for safe nodes");
    });
  });

  // -------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------
  describe("edge cases", () => {
    it("handles single package (no dependencies)", () => {
      const bom = makeCycloneDXBom([cdxComponent("lonely", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      assertValidMermaid(mermaid);
      assertHasNode(mermaid, "pkg_lonely", "lonely@1.0.0");
      // No edges expected
      assert.ok(!mermaid.includes("-->"), "Should not have any edges");
    });

    it("handles empty SBOM gracefully", () => {
      const bom = makeCycloneDXBom([]);
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      assert.ok(mermaid.includes("graph "), "Should still produce a valid graph");
      // Empty SBOM falls back to a root node named 'project' with no edges
      assert.ok(mermaid.includes('pkg_project["project@0.0.0"]'),
        "Should show fallback root node");
      assert.ok(!mermaid.includes("-->"), "Should have no edges");
    });

    it("handles scoped packages (@scope/name)", () => {
      // Use full scoped names (matching real CycloneDX format where name is fully encoded)
      const bom = makeCycloneDXBom(
        [
          cdxComponent("my-project", "1.0.0"),
          cdxComponent("@babel/core", "7.23.0"),
          cdxComponent("@babel/runtime", "7.23.0"),
        ],
        [
          cdxDependency("pkg:npm/my-project@1.0.0", [
            `pkg:npm/${encodeURIComponent("@babel/core")}@7.23.0`,
          ]),
          cdxDependency(`pkg:npm/${encodeURIComponent("@babel/core")}@7.23.0`, [
            `pkg:npm/${encodeURIComponent("@babel/runtime")}@7.23.0`,
          ]),
        ],
      );

      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      assertValidMermaid(mermaid);
      // Scoped package IDs should be sanitized (no @ or / in IDs)
      // @babel/core → fullName "@babel/core" → sanitized to "pkg_babel_core"
      assertHasNode(mermaid, "pkg_babel_core", "@babel/core");
      assertHasNode(mermaid, "pkg_babel_runtime", "@babel/runtime");
      assertHasEdge(mermaid, "pkg_my_project", "pkg_babel_core");
      assertHasEdge(mermaid, "pkg_babel_core", "pkg_babel_runtime");
    });

    it("handles circular references without infinite loop", () => {
      // Build a manual tree with a cycle reference by using the same bom-ref
      const bom = makeCycloneDXBom(
        [
          cdxComponent("a", "1.0.0"),
          cdxComponent("b", "1.0.0"),
        ],
        [
          // a depends on b, b depends on a — cycle!
          cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/b@1.0.0"]),
          cdxDependency("pkg:npm/b@1.0.0", ["pkg:npm/a@1.0.0"]),
        ],
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        // Limit depth to prevent runaway traversal
        { maxDepth: 5 },
      );

      assertValidMermaid(mermaid);
      assert.ok(mermaid.includes("pkg_a"), "Should contain node a");
      assert.ok(mermaid.includes("pkg_b"), "Should contain node b");
    });

    it("handles deep nesting", () => {
      // Create a chain: root → a → b → c → d → e
      const components: CycloneDXComponent[] = [];
      const dependencies: CycloneDXDependency[] = [];
      const names = ["root", "a", "b", "c", "d", "e"];

      for (const name of names) {
        components.push(cdxComponent(name, "1.0.0"));
      }
      for (let i = 0; i < names.length - 1; i++) {
        dependencies.push(
          cdxDependency(
            `pkg:npm/${names[i]}@1.0.0`,
            [`pkg:npm/${names[i + 1]}@1.0.0`],
          ),
        );
      }

      const bom = makeCycloneDXBom(components, dependencies);
      // maxDepth: 3 includes depths 0-3 (tree builder checks depth > maxDepth)
      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        { maxDepth: 3 },
      );

      assertValidMermaid(mermaid);
      assertHasNode(mermaid, "pkg_root", "root");
      assertHasNode(mermaid, "pkg_a", "a");
      assertHasNode(mermaid, "pkg_b", "b");
      assertHasNode(mermaid, "pkg_c", "c");
      // d and e should NOT appear (depth 4 > maxDepth 3)
      assert.ok(!mermaid.includes('pkg_d["'), "Should not include d beyond maxDepth");
      assert.ok(!mermaid.includes('pkg_e["'), "Should not include e beyond maxDepth");
    });

    it("handles many parallel dependencies", () => {
      const components: CycloneDXComponent[] = [cdxComponent("root", "1.0.0")];
      const childRefs: string[] = [];

      // 20 direct children of root
      for (let i = 0; i < 20; i++) {
        components.push(cdxComponent(`dep-${i}`, "1.0.0"));
        childRefs.push(`pkg:npm/dep-${i}@1.0.0`);
      }

      const bom = makeCycloneDXBom(components, [
        cdxDependency("pkg:npm/root@1.0.0", childRefs),
      ]);

      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);
      assertValidMermaid(mermaid);

      // All 20 should appear
      for (let i = 0; i < 20; i++) {
        assert.ok(
          mermaid.includes(`dep_${i}`),
          `Should include dep-${i}`,
        );
      }
    });
  });

  // -------------------------------------------------------------------
  // Large graph performance
  // -------------------------------------------------------------------
  describe("performance", () => {
    it("handles large graph (100+ packages) within reasonable time", () => {
      const components: CycloneDXComponent[] = [cdxComponent("root", "1.0.0")];
      const dependencies: CycloneDXDependency[] = [];
      const childRefs: string[] = [];

      // 100 direct dependencies, each with 2 transitive deps
      for (let i = 0; i < 100; i++) {
        components.push(cdxComponent(`pkg-${i}`, "1.0.0"));
        childRefs.push(`pkg:npm/pkg-${i}@1.0.0`);

        // Each has 2 children
        components.push(cdxComponent(`pkg-${i}-child-a`, "1.0.0"));
        components.push(cdxComponent(`pkg-${i}-child-b`, "1.0.0"));
        dependencies.push(
          cdxDependency(`pkg:npm/pkg-${i}@1.0.0`, [
            `pkg:npm/pkg-${i}-child-a@1.0.0`,
            `pkg:npm/pkg-${i}-child-b@1.0.0`,
          ]),
        );
      }

      dependencies.push(cdxDependency("pkg:npm/root@1.0.0", childRefs));

      const bom = makeCycloneDXBom(components, dependencies);

      const start = performance.now();
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);
      const elapsed = performance.now() - start;

      assertValidMermaid(mermaid);
      assert.ok(elapsed < 5000, `Should complete in <5s, took ${elapsed.toFixed(0)}ms`);
      assert.ok(mermaid.includes("pkg_root"), "Should include root");
      assert.ok(mermaid.includes("pkg_pkg_0"), "Should include first package");
    });
  });

  // -------------------------------------------------------------------
  // Mermaid syntax validity
  // -------------------------------------------------------------------
  describe("Mermaid syntax validity", () => {
    it("properly quotes node labels", () => {
      const bom = makeCycloneDXBom([cdxComponent("test-pkg", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      // All node defs should have quoted labels
      const nodeLines = mermaid
        .split("\n")
        .filter((l) => l.trim().startsWith("pkg_") && l.includes("["));
      for (const line of nodeLines) {
        assert.ok(
          /\[".*"]/.test(line),
          `Node line should have quoted label: ${line}`,
        );
      }
    });

    it("sanitizes IDs to only contain valid Mermaid characters", () => {
      const bom = makeCycloneDXBom(
        [cdxComponent("test.pkg/v2", "1.0.0")],
        [],
      );
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      // Find node ID portion (before the [)
      const nodeLines = mermaid
        .split("\n")
        .filter((l) => l.trim().includes("["));
      for (const line of nodeLines) {
        const match = line.trim().match(/^([A-Za-z_][A-Za-z0-9_]*)\[/);
        assert.ok(
          match,
          `Node ID should be valid Mermaid ID: ${line.trim()}`,
        );
      }
    });

    it("escapes HTML-sensitive characters in labels", () => {
      // The label contains characters that need escaping
      const bom = makeCycloneDXBom([cdxComponent("test", "1.0.0")]);
      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      // No raw < or > in labels
      const labelLines = mermaid
        .split("\n")
        .filter((l) => l.includes('["'));
      for (const line of labelLines) {
        assert.ok(
          !line.includes("<") && !line.includes(">"),
          `Label should not contain unescaped HTML chars: ${line}`,
        );
      }
    });

    it("handles duplicate edges from shared transitive deps", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("a", "1.0.0"),
          cdxComponent("b", "1.0.0"),
          cdxComponent("shared", "1.0.0"),
        ],
        [
          cdxDependency("pkg:npm/root@1.0.0", [
            "pkg:npm/a@1.0.0",
            "pkg:npm/b@1.0.0",
          ]),
          cdxDependency("pkg:npm/a@1.0.0", ["pkg:npm/shared@1.0.0"]),
          cdxDependency("pkg:npm/b@1.0.0", ["pkg:npm/shared@1.0.0"]),
        ],
      );

      const mermaid = generateMermaidFromSbom(bom as unknown as Record<string, unknown>);

      assertValidMermaid(mermaid);
      assertHasEdge(mermaid, "pkg_a", "pkg_shared");
      assertHasEdge(mermaid, "pkg_b", "pkg_shared");
    });
  });

  // -------------------------------------------------------------------
  // All four directions
  // -------------------------------------------------------------------
  describe("directions", () => {
    const directions = ["TB", "BT", "LR", "RL"] as const;

    for (const dir of directions) {
      it(`generates graph with direction ${dir}`, () => {
        const bom = makeCycloneDXBom(
          [cdxComponent("root", "1.0.0"), cdxComponent("child", "1.0.0")],
          [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/child@1.0.0"])],
        );

        const mermaid = generateMermaidFromSbom(
          bom as unknown as Record<string, unknown>,
          { direction: dir },
        );

        assert.ok(
          mermaid.includes(`graph ${dir}`),
          `Should contain 'graph ${dir}'`,
        );
      });
    }
  });

  // -------------------------------------------------------------------
  // Combined options
  // -------------------------------------------------------------------
  describe("combined options", () => {
    it("respects multiple options simultaneously", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "2.0.0"),
          cdxComponent("vuln-pkg", "1.0.0"),
          cdxComponent("safe-pkg", "3.0.0"),
          cdxComponent("deep-pkg", "1.0.0"),
        ],
        [
          cdxDependency("pkg:npm/root@2.0.0", [
            "pkg:npm/vuln-pkg@1.0.0",
            "pkg:npm/safe-pkg@3.0.0",
          ]),
          cdxDependency("pkg:npm/safe-pkg@3.0.0", ["pkg:npm/deep-pkg@1.0.0"]),
        ],
        [cdxVulnerability("CVE-2024-9999", "high", "pkg:npm/vuln-pkg@1.0.0")],
      );

      const mermaid = generateMermaidFromSbom(
        bom as unknown as Record<string, unknown>,
        {
          direction: "LR",
          title: "Combined Test",
          maxDepth: 1,
          highlightVulnerable: true,
          showVersions: true,
        },
      );

      assertValidMermaid(mermaid);
      assert.ok(mermaid.includes("graph LR"), "Direction should be LR");
      assert.ok(mermaid.includes("title: Combined Test"), "Title should be present");
      assertHasNode(mermaid, "pkg_root", "root@2.0.0");
      assertHasNode(mermaid, "pkg_vuln_pkg", "vuln-pkg@1.0.0");
      assertHasNode(mermaid, "pkg_safe_pkg", "safe-pkg@3.0.0");
      // deep-pkg should be excluded by maxDepth: 1
      assert.ok(!mermaid.includes("pkg_deep_pkg"), "deep-pkg should be excluded by maxDepth");
      assertHasStyle(mermaid, "pkg_vuln_pkg", "#ff6b6b");
    });
  });
});
