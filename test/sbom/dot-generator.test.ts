/**
 * SBOM Graphviz DOT Diagram Generator tests.
 *
 * Tests for generating valid Graphviz DOT dependency graphs from
 * CycloneDX/SPDX SBOM documents with various configuration options.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateDotFromSbom } from "../../src/sbom/dot-generator";
import type {
  CycloneDXBom,
  CycloneDXComponent,
  CycloneDXDependency,
  CycloneDXVulnerability,
  DotOptions,
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
    serialNumber: "urn:uuid:dot-test-serial",
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

/** Assert that the string is valid DOT syntax (basic structural checks). */
function assertValidDot(dot: string): void {
  // Must start with 'digraph dependencies {'
  assert.ok(
    dot.trimStart().startsWith("digraph dependencies {"),
    `Expected DOT to start with 'digraph dependencies {', got:\n${dot.slice(0, 200)}`,
  );

  // Must end with '}'
  assert.ok(
    dot.trimEnd().endsWith("}"),
    `Expected DOT to end with '}', got:\n${dot.slice(-200)}`,
  );

  // All statement lines should end with semicolons (excluding braces and blank lines)
  const lines = dot.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (
      trimmed.length === 0 ||
      trimmed === "{" ||
      trimmed === "}"
    ) {
      continue;
    }
    assert.ok(
      trimmed.endsWith(";") || trimmed.endsWith("{") || trimmed === "}",
      `Statement line should end with semicolon: "${trimmed}"`,
    );
  }
}

/** Assert the DOT string contains a node definition with the given ID. */
function assertHasNode(dot: string, id: string, labelContains?: string): void {
  const nodeRegex = new RegExp(`^\\s+${id}\\s+\\[.*?\\]`, "m");
  assert.ok(
    nodeRegex.test(dot),
    `Expected node definition for ${id}, got:\n${dot.slice(0, 500)}`,
  );
  if (labelContains) {
    const labelRegex = new RegExp(
      `^\\s+${id}\\s+\\[label="[^"]*${labelContains.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[^"]*"`,
      "m",
    );
    assert.ok(
      labelRegex.test(dot),
      `Expected node ${id} with label containing "${labelContains}", got:\n${dot.slice(0, 500)}`,
    );
  }
}

/** Assert the DOT string contains an edge from → to. */
function assertHasEdge(dot: string, from: string, to: string): void {
  const edgeRegex = new RegExp(
    `^\\s+${from}\\s+->\\s+${to}\\s*;`,
    "m",
  );
  assert.ok(
    edgeRegex.test(dot),
    `Expected edge ${from} -> ${to}, got:\n${dot.slice(0, 500)}`,
  );
}

/** Assert the DOT string contains a node with the given fill color. */
function assertHasFillcolor(dot: string, id: string, fillColor: string): void {
  const colorRegex = new RegExp(
    `^\\s+${id}\\s+\\[[^\\]]*fillcolor="${fillColor.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"[^\\]]*\\]`,
    "m",
  );
  assert.ok(
    colorRegex.test(dot),
    `Expected node ${id} with fillcolor="${fillColor}", got:\n${dot.slice(0, 500)}`,
  );
}

/** Assert the DOT string does NOT contain a node definition. */
function assertNoNode(dot: string, id: string): void {
  const nodeRegex = new RegExp(`^\\s+${id}\\s+\\[`, "m");
  assert.ok(
    !nodeRegex.test(dot),
    `Should not contain node definition for ${id}, got:\n${dot.slice(0, 500)}`,
  );
}

// ============================================================================
// Tests
// ============================================================================

describe("generateDotFromSbom", () => {
  // -------------------------------------------------------------------
  // Basic CycloneDX output
  // -------------------------------------------------------------------
  describe("CycloneDX SBOM", () => {
    it("generates valid DOT output from CycloneDX SBOM", () => {
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
          cdxDependency("pkg:npm/body-parser@1.20.0", [
            "pkg:npm/bytes@3.1.2",
          ]),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      assertValidDot(dot);
      assertHasNode(dot, "pkg_my_project", "my-project@1.0.0");
      assertHasNode(dot, "pkg_express", "express@4.18.2");
      assertHasNode(dot, "pkg_body_parser", "body-parser@1.20.0");
      assertHasNode(dot, "pkg_bytes", "bytes@3.1.2");
      assertHasNode(dot, "pkg_cookie", "cookie@0.5.0");
      assertHasEdge(dot, "pkg_my_project", "pkg_express");
      assertHasEdge(dot, "pkg_express", "pkg_body_parser");
      assertHasEdge(dot, "pkg_express", "pkg_cookie");
      assertHasEdge(dot, "pkg_body_parser", "pkg_bytes");
    });

    it("uses TB rankdir by default", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );
      assert.ok(
        dot.includes("rankdir=TB"),
        "Default rankdir should be TB",
      );
    });

    it("respects rankdir option (LR)", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { rankdir: "LR" },
      );
      assert.ok(dot.includes("rankdir=LR"), "Rankdir should be LR");
    });

    it("respects rankdir option (BT)", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { rankdir: "BT" },
      );
      assert.ok(dot.includes("rankdir=BT"));
    });

    it("respects rankdir option (RL)", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { rankdir: "RL" },
      );
      assert.ok(dot.includes("rankdir=RL"));
    });

    it("includes title when specified", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { title: "My Project Dependency Graph" },
      );
      assert.ok(
        dot.includes('label="My Project Dependency Graph"'),
        "Should include title label",
      );
      assert.ok(dot.includes("labelloc=t"), "Should set label location top");
      assert.ok(
        dot.includes('fontname="Helvetica-Bold"'),
        "Should set title font",
      );
    });

    it("omits title attributes when not specified", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );
      assert.ok(!dot.includes("labelloc="), "Should not have labelloc");
      assert.ok(
        !dot.includes("fontsize="),
        "Should not have fontsize",
      );
    });

    it("hides versions when showVersions is false", () => {
      const bom = makeCycloneDXBom([cdxComponent("express", "4.18.2")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { showVersions: false },
      );
      // Label should contain "express" but not "4.18.2"
      assert.ok(
        dot.includes('label="express"'),
        "Label should be just the name",
      );
      assert.ok(!dot.includes("4.18.2"), "Should not include version");
    });

    it("shows versions by default", () => {
      const bom = makeCycloneDXBom([cdxComponent("express", "4.18.2")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );
      assert.ok(dot.includes("express@4.18.2"), "Should include version");
    });
  });

  // -------------------------------------------------------------------
  // SPDX SBOM output
  // -------------------------------------------------------------------
  describe("SPDX SBOM", () => {
    it("generates valid DOT output from SPDX SBOM", () => {
      const doc = makeSpdxDoc(
        [
          spdxPackage("SPDXRef-DOCUMENT", "test-project", "NOASSERTION"),
          spdxPackage("SPDXRef-express", "express", "4.18.2"),
          spdxPackage("SPDXRef-lodash", "lodash", "4.17.21"),
        ],
        [
          spdxRelationship(
            "SPDXRef-DOCUMENT",
            "DESCRIBES",
            "SPDXRef-express",
          ),
          spdxRelationship(
            "SPDXRef-express",
            "DEPENDS_ON",
            "SPDXRef-lodash",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        doc as unknown as Record<string, unknown>,
      );

      assertValidDot(dot);
      assertHasNode(dot, "pkg_express", "express@4.18.2");
      assertHasNode(dot, "pkg_lodash", "lodash@4.17.21");
      assertHasEdge(dot, "pkg_express", "pkg_lodash");
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
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { maxDepth: 1 },
      );

      assertValidDot(dot);
      assertHasNode(dot, "pkg_root", "root@1.0.0");
      assertHasNode(dot, "pkg_a", "a@1.0.0");
      // b should NOT appear (depth 2 > maxDepth 1)
      assertNoNode(dot, "pkg_b");
      assertNoNode(dot, "pkg_c");
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

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );
      assertHasNode(dot, "pkg_root", "root");
      assertHasNode(dot, "pkg_a", "a");
      assertHasNode(dot, "pkg_b", "b");
    });
  });

  // -------------------------------------------------------------------
  // Vulnerability highlighting
  // -------------------------------------------------------------------
  describe("vulnerability highlighting", () => {
    it("highlights critical/high vulnerabilities with red (#ffcdd2)", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("vuln-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/vuln-pkg@1.0.0"])],
        [
          cdxVulnerability(
            "CVE-2024-0001",
            "critical",
            "pkg:npm/vuln-pkg@1.0.0",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertValidDot(dot);
      assertHasFillcolor(dot, "pkg_vuln_pkg", "#ffcdd2");
    });

    it("highlights high vulnerabilities with red (#ffcdd2)", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("high-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/high-pkg@1.0.0"])],
        [
          cdxVulnerability(
            "CVE-2024-0010",
            "high",
            "pkg:npm/high-pkg@1.0.0",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertHasFillcolor(dot, "pkg_high_pkg", "#ffcdd2");
    });

    it("highlights medium vulnerabilities with orange (#ffe0b2)", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("medium-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/medium-pkg@1.0.0"])],
        [
          cdxVulnerability(
            "CVE-2024-0002",
            "medium",
            "pkg:npm/medium-pkg@1.0.0",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertHasFillcolor(dot, "pkg_medium_pkg", "#ffe0b2");
    });

    it("highlights low vulnerabilities with yellow (#fff9c4)", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("low-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/low-pkg@1.0.0"])],
        [
          cdxVulnerability(
            "CVE-2024-0003",
            "low",
            "pkg:npm/low-pkg@1.0.0",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertHasFillcolor(dot, "pkg_low_pkg", "#fff9c4");
    });

    it("picks highest severity when multiple vulnerabilities", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("multi-vuln", "1.0.0"),
        ],
        [
          cdxDependency("pkg:npm/root@1.0.0", [
            "pkg:npm/multi-vuln@1.0.0",
          ]),
        ],
        [
          cdxVulnerability(
            "CVE-2024-0001",
            "low",
            "pkg:npm/multi-vuln@1.0.0",
          ),
          cdxVulnerability(
            "CVE-2024-0002",
            "critical",
            "pkg:npm/multi-vuln@1.0.0",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      // Should use critical color (red), not low (yellow)
      assertHasFillcolor(dot, "pkg_multi_vuln", "#ffcdd2");
    });

    it("uses safe green color when highlightVulnerable is false", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("vuln-pkg", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/vuln-pkg@1.0.0"])],
        [
          cdxVulnerability(
            "CVE-2024-0001",
            "critical",
            "pkg:npm/vuln-pkg@1.0.0",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: false },
      );

      // All nodes should be safe green
      assertHasFillcolor(dot, "pkg_vuln_pkg", "#e8f5e9");
    });

    it("uses safe green for nodes without vulnerabilities", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("safe", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/safe@1.0.0"])],
        // No vulnerabilities
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { highlightVulnerable: true },
      );

      assertHasFillcolor(dot, "pkg_safe", "#e8f5e9");
    });
  });

  // -------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------
  describe("edge cases", () => {
    it("handles single package (no dependencies)", () => {
      const bom = makeCycloneDXBom([cdxComponent("lonely", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      assertValidDot(dot);
      assertHasNode(dot, "pkg_lonely", "lonely@1.0.0");
      // No edges expected — only the root node line
      const edgeLines = dot
        .split("\n")
        .filter((l) => l.trim().includes("->"));
      assert.equal(
        edgeLines.length,
        0,
        "Should not have any edges",
      );
    });

    it("handles empty SBOM gracefully", () => {
      const bom = makeCycloneDXBom([]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      assertValidDot(dot);
      // Empty graph should still have a valid structure
      assert.ok(dot.includes("digraph dependencies {"));
      assert.ok(dot.endsWith("}"));
    });

    it("handles scoped packages (@scope/name)", () => {
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
          cdxDependency(
            `pkg:npm/${encodeURIComponent("@babel/core")}@7.23.0`,
            [
              `pkg:npm/${encodeURIComponent("@babel/runtime")}@7.23.0`,
            ],
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      assertValidDot(dot);
      // @babel/core → sanitized to pkg_babel_core
      assertHasNode(dot, "pkg_babel_core", "@babel/core");
      assertHasNode(dot, "pkg_babel_runtime", "@babel/runtime");
      assertHasEdge(dot, "pkg_my_project", "pkg_babel_core");
      assertHasEdge(dot, "pkg_babel_core", "pkg_babel_runtime");
    });

    it("handles circular references without infinite loop", () => {
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

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { maxDepth: 5 },
      );

      assertValidDot(dot);
      assert.ok(dot.includes("pkg_a"), "Should contain node a");
      assert.ok(dot.includes("pkg_b"), "Should contain node b");
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
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        { maxDepth: 3 },
      );

      assertValidDot(dot);
      assertHasNode(dot, "pkg_root", "root");
      assertHasNode(dot, "pkg_a", "a");
      assertHasNode(dot, "pkg_b", "b");
      assertHasNode(dot, "pkg_c", "c");
      // d and e should NOT appear (depth 4 > maxDepth 3)
      assertNoNode(dot, "pkg_d");
      assertNoNode(dot, "pkg_e");
    });

    it("handles many parallel dependencies", () => {
      const components: CycloneDXComponent[] = [
        cdxComponent("root", "1.0.0"),
      ];
      const childRefs: string[] = [];

      // 20 direct children of root
      for (let i = 0; i < 20; i++) {
        components.push(cdxComponent(`dep-${i}`, "1.0.0"));
        childRefs.push(`pkg:npm/dep-${i}@1.0.0`);
      }

      const bom = makeCycloneDXBom(components, [
        cdxDependency("pkg:npm/root@1.0.0", childRefs),
      ]);

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );
      assertValidDot(dot);

      // All 20 should appear
      for (let i = 0; i < 20; i++) {
        assert.ok(
          dot.includes(`dep_${i}`),
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
      const components: CycloneDXComponent[] = [
        cdxComponent("root", "1.0.0"),
      ];
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
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );
      const elapsed = performance.now() - start;

      assertValidDot(dot);
      assert.ok(
        elapsed < 5000,
        `Should complete in <5s, took ${elapsed.toFixed(0)}ms`,
      );
      assert.ok(dot.includes("pkg_root"), "Should include root");
      assert.ok(dot.includes("pkg_pkg_0"), "Should include first package");
    });
  });

  // -------------------------------------------------------------------
  // DOT syntax validity
  // -------------------------------------------------------------------
  describe("DOT syntax validity", () => {
    it("properly quotes node labels in double quotes", () => {
      const bom = makeCycloneDXBom([cdxComponent("test-pkg", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      // All node defs should have quoted labels
      const nodeLines = dot
        .split("\n")
        .filter(
          (l) =>
            l.trim().startsWith("pkg_") && l.includes("["),
        );
      for (const line of nodeLines) {
        assert.ok(
          /label="[^"]*"/.test(line),
          `Node line should have quoted label: ${line}`,
        );
      }
    });

    it("sanitizes node IDs to only contain valid DOT characters", () => {
      const bom = makeCycloneDXBom(
        [cdxComponent("test.pkg/v2", "1.0.0")],
        [],
      );
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      // Find node ID portion (before the [)
      const nodeLines = dot
        .split("\n")
        .filter((l) => l.trim().includes("["));
      for (const line of nodeLines) {
        const match = line.trim().match(/^([A-Za-z_][A-Za-z0-9_]*)\s*\[/);
        assert.ok(
          match,
          `Node ID should be valid DOT ID: ${line.trim()}`,
        );
      }
    });

    it("escapes double quotes in labels", () => {
      // While unlikely in package names, verify escaping works
      const bom = makeCycloneDXBom([cdxComponent("test", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      // No unbalanced quotes — count quotes
      const quoteCount = (dot.match(/"/g) ?? []).length;
      assert.equal(
        quoteCount % 2,
        0,
        "Should have balanced double quotes",
      );
    });

    it("uses proper semicolons for all statements", () => {
      const bom = makeCycloneDXBom(
        [
          cdxComponent("root", "1.0.0"),
          cdxComponent("child", "1.0.0"),
        ],
        [cdxDependency("pkg:npm/root@1.0.0", ["pkg:npm/child@1.0.0"])],
      );
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      // All non-empty, non-brace lines end with semicolons
      const lines = dot.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (
          trimmed === "" ||
          trimmed.endsWith("{") ||
          trimmed === "}"
        ) continue;
        assert.ok(
          trimmed.endsWith(";"),
          `Line should end with semicolon: "${trimmed}"`,
        );
      }
    });

    it("uses proper braces for the digraph block", () => {
      const bom = makeCycloneDXBom([cdxComponent("root", "1.0.0")]);
      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      const openBraces = (dot.match(/{/g) ?? []).length;
      const closeBraces = (dot.match(/}/g) ?? []).length;
      assert.equal(
        openBraces,
        closeBraces,
        "Should have balanced braces",
      );
      assert.equal(openBraces, 1, "Should have exactly one opening brace");
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

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
      );

      assertValidDot(dot);
      assertHasEdge(dot, "pkg_a", "pkg_shared");
      assertHasEdge(dot, "pkg_b", "pkg_shared");
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
          [
            cdxComponent("root", "1.0.0"),
            cdxComponent("child", "1.0.0"),
          ],
          [
            cdxDependency("pkg:npm/root@1.0.0", [
              "pkg:npm/child@1.0.0",
            ]),
          ],
        );

        const dot = generateDotFromSbom(
          bom as unknown as Record<string, unknown>,
          { rankdir: dir },
        );

        assert.ok(
          dot.includes(`rankdir=${dir}`),
          `Should contain 'rankdir=${dir}'`,
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
          cdxDependency("pkg:npm/safe-pkg@3.0.0", [
            "pkg:npm/deep-pkg@1.0.0",
          ]),
        ],
        [
          cdxVulnerability(
            "CVE-2024-9999",
            "high",
            "pkg:npm/vuln-pkg@1.0.0",
          ),
        ],
      );

      const dot = generateDotFromSbom(
        bom as unknown as Record<string, unknown>,
        {
          rankdir: "LR",
          title: "Combined Test",
          maxDepth: 1,
          highlightVulnerable: true,
          showVersions: true,
        },
      );

      assertValidDot(dot);
      assert.ok(dot.includes("rankdir=LR"), "Rankdir should be LR");
      assert.ok(
        dot.includes('label="Combined Test"'),
        "Title should be present",
      );
      assertHasNode(dot, "pkg_root", "root@2.0.0");
      assertHasNode(dot, "pkg_vuln_pkg", "vuln-pkg@1.0.0");
      assertHasNode(dot, "pkg_safe_pkg", "safe-pkg@3.0.0");
      // deep-pkg should be excluded by maxDepth: 1
      assertNoNode(dot, "pkg_deep_pkg");
      assertHasFillcolor(dot, "pkg_vuln_pkg", "#ffcdd2");
    });
  });
});
