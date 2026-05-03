/**
 * SBOM diffing module tests.
 *
 * Tests for comparing two SBOM documents (CycloneDX and SPDX),
 * including cross-format comparisons, edge cases, and error handling.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { diffSbom, formatDiffResult } from "../../src/sbom/diff";
import type {
  CycloneDXBom,
  CycloneDXComponent,
  SPDXDocument,
  SPDXPackage,
  SbomDiffResult,
} from "../../src/sbom/types";

// ============================================================================
// Test Fixtures: CycloneDX
// ============================================================================

function makeCycloneDXBom(components: CycloneDXComponent[]): CycloneDXBom {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:test-serial",
    version: 1,
    metadata: {
      timestamp: "2025-05-01T00:00:00.000Z",
      tools: [
        { vendor: "test", name: "test-tool", version: "1.0.0" },
      ],
    },
    components,
  };
}

const cycloneDXComponentA: CycloneDXComponent = {
  type: "library",
  "bom-ref": "pkg:npm/lodash@4.17.21",
  name: "lodash",
  version: "4.17.21",
  purl: "pkg:npm/lodash@4.17.21",
};

const cycloneDXComponentB: CycloneDXComponent = {
  type: "library",
  "bom-ref": "pkg:npm/express@4.18.2",
  name: "express",
  version: "4.18.2",
  purl: "pkg:npm/express@4.18.2",
};

const cycloneDXComponentC: CycloneDXComponent = {
  type: "library",
  "bom-ref": "pkg:npm/minimist@1.2.6",
  name: "minimist",
  version: "1.2.6",
  purl: "pkg:npm/minimist@1.2.6",
};

const cycloneDXComponentScoped: CycloneDXComponent = {
  type: "library",
  "bom-ref": "pkg:npm/%40scope%2Fpackage@2.0.0",
  name: "@scope/package",
  version: "2.0.0",
  purl: "pkg:npm/%40scope%2Fpackage@2.0.0",
};

// ============================================================================
// Test Fixtures: SPDX
// ============================================================================

function makeSPDXDoc(packages: SPDXPackage[]): SPDXDocument {
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
    packages: [
      // Root document package (should be skipped)
      {
        SPDXID: "SPDXRef-DOCUMENT",
        name: "test-project",
        versionInfo: "NOASSERTION",
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        licenseConcluded: "NOASSERTION",
        licenseDeclared: "NOASSERTION",
        copyrightText: "NOASSERTION",
      },
      ...packages,
    ],
    relationships: [],
  };
}

function spdxPkg(
  name: string,
  version: string,
  purl?: string,
): SPDXPackage {
  const pkg: SPDXPackage = {
    SPDXID: `SPDXRef-Package-${name.replace(/[/@]/g, "-").replace(/^-/, "")}`,
    name,
    versionInfo: version,
    downloadLocation: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    filesAnalyzed: false,
    licenseConcluded: "MIT",
    licenseDeclared: "MIT",
    copyrightText: "NOASSERTION",
  };
  if (purl) {
    pkg.externalRefs = [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: purl,
      },
    ];
  }
  return pkg;
}

// ============================================================================
// Tests: CycloneDX vs CycloneDX
// ============================================================================

describe("diffSbom - CycloneDX", () => {
  it("should detect no changes for identical SBOMs", () => {
    const bom = makeCycloneDXBom([cycloneDXComponentA, cycloneDXComponentB]);
    const result = diffSbom(bom, bom);

    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 0);
    assert.equal(result.summary.totalUpdated, 0);
    assert.equal(result.summary.totalUnchanged, 2);
  });

  it("should detect added dependencies", () => {
    const old = makeCycloneDXBom([cycloneDXComponentA]);
    const new_ = makeCycloneDXBom([cycloneDXComponentA, cycloneDXComponentB]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 1);
    assert.equal(result.summary.totalRemoved, 0);
    assert.equal(result.summary.totalUpdated, 0);
    assert.equal(result.summary.totalUnchanged, 1);
    assert.equal(result.added[0].name, "express");
    assert.equal(result.added[0].version, "4.18.2");
  });

  it("should detect removed dependencies", () => {
    const old = makeCycloneDXBom([cycloneDXComponentA, cycloneDXComponentB]);
    const new_ = makeCycloneDXBom([cycloneDXComponentA]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 1);
    assert.equal(result.removed[0].name, "express");
    assert.equal(result.removed[0].version, "4.18.2");
  });

  it("should detect updated dependencies (version change)", () => {
    const oldComp: CycloneDXComponent = {
      ...cycloneDXComponentC,
      version: "1.2.5",
      "bom-ref": "pkg:npm/minimist@1.2.5",
      purl: "pkg:npm/minimist@1.2.5",
    };
    const newComp: CycloneDXComponent = {
      ...cycloneDXComponentC,
      version: "1.2.6",
      "bom-ref": "pkg:npm/minimist@1.2.6",
      purl: "pkg:npm/minimist@1.2.6",
    };

    const old = makeCycloneDXBom([oldComp]);
    const new_ = makeCycloneDXBom([newComp]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUpdated, 1);
    assert.equal(result.updated[0].name, "minimist");
    assert.equal(result.updated[0].previousVersion, "1.2.5");
    assert.equal(result.updated[0].version, "1.2.6");
  });

  it("should handle mixed adds, removes, and updates", () => {
    const oldComp1: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
    };
    const oldComp2: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/express@4.18.0",
      name: "express",
      version: "4.18.0",
      purl: "pkg:npm/express@4.18.0",
    };
    const oldComp3: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/body-parser@1.20.0",
      name: "body-parser",
      version: "1.20.0",
      purl: "pkg:npm/body-parser@1.20.0",
    };

    const newComp1: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
    };
    const newComp2: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/express@4.19.0",
      name: "express",
      version: "4.19.0",
      purl: "pkg:npm/express@4.19.0",
    };
    const newComp3: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/minimist@1.2.6",
      name: "minimist",
      version: "1.2.6",
      purl: "pkg:npm/minimist@1.2.6",
    };

    const old = makeCycloneDXBom([oldComp1, oldComp2, oldComp3]);
    const new_ = makeCycloneDXBom([newComp1, newComp2, newComp3]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUnchanged, 1); // lodash
    assert.equal(result.summary.totalUpdated, 1);   // express 4.18.0 -> 4.19.0
    assert.equal(result.summary.totalRemoved, 1);   // body-parser
    assert.equal(result.summary.totalAdded, 1);     // minimist

    assert.equal(result.unchanged[0].name, "lodash");
    assert.equal(result.updated[0].name, "express");
    assert.equal(result.updated[0].previousVersion, "4.18.0");
    assert.equal(result.removed[0].name, "body-parser");
    assert.equal(result.added[0].name, "minimist");
  });

  it("should handle empty old SBOM (all added)", () => {
    const old = makeCycloneDXBom([]);
    const new_ = makeCycloneDXBom([cycloneDXComponentA, cycloneDXComponentB]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 2);
    assert.equal(result.summary.totalRemoved, 0);
    assert.equal(result.summary.totalUpdated, 0);
    assert.equal(result.summary.totalUnchanged, 0);
  });

  it("should handle empty new SBOM (all removed)", () => {
    const old = makeCycloneDXBom([cycloneDXComponentA, cycloneDXComponentB]);
    const new_ = makeCycloneDXBom([]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 2);
    assert.equal(result.summary.totalUpdated, 0);
    assert.equal(result.summary.totalUnchanged, 0);
  });

  it("should handle both SBOMs empty", () => {
    const old = makeCycloneDXBom([]);
    const new_ = makeCycloneDXBom([]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 0);
    assert.equal(result.summary.totalUpdated, 0);
    assert.equal(result.summary.totalUnchanged, 0);
  });

  it("should handle components without purl (fallback to bom-ref/name)", () => {
    const compWithoutPurl: CycloneDXComponent = {
      type: "library",
      "bom-ref": "my-custom-ref",
      name: "custom-pkg",
      version: "1.0.0",
    };
    const old = makeCycloneDXBom([compWithoutPurl]);
    const new_ = makeCycloneDXBom([compWithoutPurl]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUnchanged, 1);
    assert.equal(result.unchanged[0].name, "custom-pkg");
    assert.equal(result.unchanged[0].purl, "my-custom-ref");
  });

  it("should handle components with no bom-ref or purl (use name as key)", () => {
    const compMinimal: CycloneDXComponent = {
      type: "library",
      "bom-ref": "",
      name: "minimal-pkg",
      version: "1.0.0",
      purl: "",
    };
    const old = makeCycloneDXBom([compMinimal]);
    const new_ = makeCycloneDXBom([compMinimal]);
    const result = diffSbom(old, new_);

    // Empty string purl will be falsy, so key falls back to name
    assert.equal(result.summary.totalUnchanged, 1);
  });

  it("should set metadata correctly", () => {
    const old = makeCycloneDXBom([cycloneDXComponentA]);
    const new_ = makeCycloneDXBom([cycloneDXComponentA]);
    const result = diffSbom(old, new_);

    assert.equal(result.metadata.oldFormat, "cyclonedx");
    assert.equal(result.metadata.newFormat, "cyclonedx");
    assert.ok(result.metadata.comparedAt);
    // Verify it's a valid ISO date string
    assert.ok(!isNaN(Date.parse(result.metadata.comparedAt)));
  });

  it("should sort results alphabetically by name", () => {
    const zComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/zebra@1.0.0",
      name: "zebra",
      version: "1.0.0",
      purl: "pkg:npm/zebra@1.0.0",
    };
    const aComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/alpha@1.0.0",
      name: "alpha",
      version: "1.0.0",
      purl: "pkg:npm/alpha@1.0.0",
    };
    const mComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/middle@1.0.0",
      name: "middle",
      version: "1.0.0",
      purl: "pkg:npm/middle@1.0.0",
    };

    // Old has zebra, alpha; New has alpha, middle, zebra (different order)
    const old = makeCycloneDXBom([zComp, aComp]);
    const new_ = makeCycloneDXBom([aComp, mComp, zComp]);
    const result = diffSbom(old, new_);

    assert.equal(result.added[0].name, "middle");
    assert.equal(result.unchanged[0].name, "alpha");
    assert.equal(result.unchanged[1].name, "zebra");
  });
});

// ============================================================================
// Tests: SPDX vs SPDX
// ============================================================================

describe("diffSbom - SPDX", () => {
  it("should detect no changes for identical SPDX SBOMs", () => {
    const doc = makeSPDXDoc([
      spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
      spdxPkg("express", "4.18.2", "pkg:npm/express@4.18.2"),
    ]);
    const result = diffSbom(doc, doc);

    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 0);
    assert.equal(result.summary.totalUpdated, 0);
    assert.equal(result.summary.totalUnchanged, 2);
  });

  it("should detect added dependencies in SPDX", () => {
    const old = makeSPDXDoc([spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")]);
    const new_ = makeSPDXDoc([
      spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
      spdxPkg("express", "4.18.2", "pkg:npm/express@4.18.2"),
    ]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 1);
    assert.equal(result.added[0].name, "express");
    assert.equal(result.added[0].version, "4.18.2");
  });

  it("should detect removed dependencies in SPDX", () => {
    const old = makeSPDXDoc([
      spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
      spdxPkg("express", "4.18.2", "pkg:npm/express@4.18.2"),
    ]);
    const new_ = makeSPDXDoc([spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalRemoved, 1);
    assert.equal(result.removed[0].name, "express");
  });

  it("should detect updated dependencies in SPDX", () => {
    const old = makeSPDXDoc([spdxPkg("minimist", "1.2.5", "pkg:npm/minimist@1.2.5")]);
    const new_ = makeSPDXDoc([spdxPkg("minimist", "1.2.6", "pkg:npm/minimist@1.2.6")]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUpdated, 1);
    assert.equal(result.updated[0].name, "minimist");
    assert.equal(result.updated[0].previousVersion, "1.2.5");
    assert.equal(result.updated[0].version, "1.2.6");
  });

  it("should skip SPDXRef-DOCUMENT package", () => {
    const old = makeSPDXDoc([]);
    const new_ = makeSPDXDoc([]);
    const result = diffSbom(old, new_);

    // The root SPDXRef-DOCUMENT should not appear in diff
    assert.equal(result.summary.totalUnchanged, 0);
  });

  it("should handle packages without purl in SPDX (use name as key)", () => {
    const old = makeSPDXDoc([spdxPkg("lodash", "4.17.21")]);
    const new_ = makeSPDXDoc([spdxPkg("lodash", "4.17.21")]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUnchanged, 1);
    assert.equal(result.unchanged[0].name, "lodash");
    assert.equal(result.unchanged[0].purl, undefined);
  });

  it("should handle NOASSERTION version in SPDX", () => {
    const pkgNoVersion: SPDXPackage = {
      SPDXID: "SPDXRef-Package-unknown",
      name: "unknown-pkg",
      versionInfo: "NOASSERTION",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
    };
    const old = makeSPDXDoc([pkgNoVersion]);
    const new_ = makeSPDXDoc([pkgNoVersion]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUnchanged, 1);
    // NOASSERTION should be normalized to "0.0.0"
    assert.equal(result.unchanged[0].version, "0.0.0");
  });

  it("should set metadata correctly for SPDX", () => {
    const doc = makeSPDXDoc([spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")]);
    const result = diffSbom(doc, doc);

    assert.equal(result.metadata.oldFormat, "spdx");
    assert.equal(result.metadata.newFormat, "spdx");
    assert.ok(result.metadata.comparedAt);
  });
});

// ============================================================================
// Tests: Cross-format (CycloneDX vs SPDX)
// ============================================================================

describe("diffSbom - Cross-format", () => {
  it("should compare CycloneDX (old) vs SPDX (new)", () => {
    const cycloneDX = makeCycloneDXBom([
      cycloneDXComponentA,
      cycloneDXComponentB,
    ]);
    const spdx = makeSPDXDoc([
      spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
      spdxPkg("minimist", "1.2.6", "pkg:npm/minimist@1.2.6"),
    ]);

    const result = diffSbom(cycloneDX, spdx);

    assert.equal(result.metadata.oldFormat, "cyclonedx");
    assert.equal(result.metadata.newFormat, "spdx");
    assert.equal(result.summary.totalUnchanged, 1); // lodash (same purl)
    assert.equal(result.summary.totalAdded, 1);     // minimist
    assert.equal(result.summary.totalRemoved, 1);   // express
    assert.equal(result.summary.totalUpdated, 0);
  });

  it("should compare SPDX (old) vs CycloneDX (new)", () => {
    const spdx = makeSPDXDoc([
      spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
    ]);
    const cycloneDX = makeCycloneDXBom([
      cycloneDXComponentA, // lodash@4.17.21
      cycloneDXComponentB, // express@4.18.2
    ]);

    const result = diffSbom(spdx, cycloneDX);

    assert.equal(result.metadata.oldFormat, "spdx");
    assert.equal(result.metadata.newFormat, "cyclonedx");
    assert.equal(result.summary.totalUnchanged, 1); // lodash
    assert.equal(result.summary.totalAdded, 1);     // express
    assert.equal(result.summary.totalRemoved, 0);
  });

  it("should match packages across formats by purl", () => {
    // Old: CycloneDX with lodash
    const cycloneDX = makeCycloneDXBom([
      { ...cycloneDXComponentA, version: "4.17.20", "bom-ref": "pkg:npm/lodash@4.17.20", purl: "pkg:npm/lodash@4.17.20" },
    ]);

    // New: SPDX with lodash (different version)
    const spdx = makeSPDXDoc([
      spdxPkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
    ]);

    const result = diffSbom(cycloneDX, spdx);

    // Same package, different version -> updated
    assert.equal(result.summary.totalUpdated, 1);
    assert.equal(result.updated[0].name, "lodash");
    assert.equal(result.updated[0].previousVersion, "4.17.20");
    assert.equal(result.updated[0].version, "4.17.21");
  });
});

// ============================================================================
// Tests: Options
// ============================================================================

describe("diffSbom - Options", () => {
  it("should support ignoreVersions option", () => {
    const oldComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.20",
      name: "lodash",
      version: "4.17.20",
      purl: "pkg:npm/lodash@4.17.20",
    };
    const newComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
    };

    const old = makeCycloneDXBom([oldComp]);
    const new_ = makeCycloneDXBom([newComp]);
    const result = diffSbom(old, new_, { ignoreVersions: true });

    // With ignoreVersions, version change should be treated as unchanged
    assert.equal(result.summary.totalUpdated, 0);
    assert.equal(result.summary.totalUnchanged, 1);
    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 0);
  });

  it("should support custom keyFn option", () => {
    // Use name-only as key to make a different package match
    const oldComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.20",
      name: "lodash",
      version: "4.17.20",
      purl: "pkg:npm/lodash@4.17.20",
    };
    const newComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
    };

    const old = makeCycloneDXBom([oldComp]);
    const new_ = makeCycloneDXBom([newComp]);
    const result = diffSbom(old, new_, {
      keyFn: (pkg) => pkg.name,
    });

    // With name-only key, same name matches but version differs -> updated
    assert.equal(result.summary.totalUnchanged, 0);
    assert.equal(result.summary.totalUpdated, 1);
    assert.equal(result.updated[0].name, "lodash");
  });
});

// ============================================================================
// Tests: Error Handling
// ============================================================================

describe("diffSbom - Error Handling", () => {
  it("should throw for null old SBOM", () => {
    assert.throws(
      () => diffSbom(null as unknown as Record<string, unknown>, {}),
      /Invalid old SBOM/,
    );
  });

  it("should throw for null new SBOM", () => {
    assert.throws(
      () => diffSbom({}, null as unknown as Record<string, unknown>),
      /Invalid new SBOM/,
    );
  });

  it("should throw for undefined old SBOM", () => {
    assert.throws(
      () => diffSbom(undefined as unknown as Record<string, unknown>, {}),
      /Invalid old SBOM/,
    );
  });

  it("should throw for unrecognized old format", () => {
    assert.throws(
      () => diffSbom({ foo: "bar" }, { bomFormat: "CycloneDX", specVersion: "1.5" }),
      /Unrecognized old SBOM format/,
    );
  });

  it("should throw for unrecognized new format", () => {
    assert.throws(
      () => diffSbom({ bomFormat: "CycloneDX", specVersion: "1.5" }, { foo: "bar" }),
      /Unrecognized new SBOM format/,
    );
  });

  it("should throw for arrays instead of objects", () => {
    assert.throws(
      () => diffSbom([] as unknown as Record<string, unknown>, {}),
      /Invalid old SBOM/,
    );
  });

  it("should handle missing components array in CycloneDX gracefully", () => {
    const old = { bomFormat: "CycloneDX", specVersion: "1.5", metadata: { timestamp: "", tools: [] } };
    const new_ = { bomFormat: "CycloneDX", specVersion: "1.5", metadata: { timestamp: "", tools: [] } };
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 0);
    assert.equal(result.summary.totalUnchanged, 0);
  });

  it("should handle missing packages array in SPDX gracefully", () => {
    const old = { spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT" };
    const new_ = { spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT" };
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 0);
    assert.equal(result.summary.totalRemoved, 0);
    assert.equal(result.summary.totalUnchanged, 0);
  });
});

// ============================================================================
// Tests: formatDiffResult
// ============================================================================

describe("formatDiffResult", () => {
  it("should format a complete diff report", () => {
    const old = makeCycloneDXBom([
      cycloneDXComponentA, // lodash
      cycloneDXComponentB, // express
    ]);
    const new_ = makeCycloneDXBom([
      cycloneDXComponentA, // lodash (unchanged)
      cycloneDXComponentC, // minimist (added)
    ]);

    const result = diffSbom(old, new_);
    const formatted = formatDiffResult(result);

    assert.ok(formatted.includes("SBOM Diff Report"));
    assert.ok(formatted.includes("Summary"));
    assert.ok(formatted.includes("Added Dependencies"));
    assert.ok(formatted.includes("minimist@1.2.6"));
    assert.ok(formatted.includes("Removed Dependencies"));
    assert.ok(formatted.includes("express@4.18.2"));
    assert.ok(formatted.includes("Unchanged Dependencies"));
    assert.ok(formatted.includes("lodash@4.17.21"));
  });

  it("should include updated entries in format output", () => {
    const oldComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/minimist@1.2.5",
      name: "minimist",
      version: "1.2.5",
      purl: "pkg:npm/minimist@1.2.5",
    };
    const newComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/minimist@1.2.6",
      name: "minimist",
      version: "1.2.6",
      purl: "pkg:npm/minimist@1.2.6",
    };

    const old = makeCycloneDXBom([oldComp]);
    const new_ = makeCycloneDXBom([newComp]);
    const result = diffSbom(old, new_);
    const formatted = formatDiffResult(result);

    assert.ok(formatted.includes("Updated Dependencies"));
    assert.ok(formatted.includes("minimist@1.2.5 -> 1.2.6"));
  });

  it("should include purl in formatted output when available", () => {
    const old = makeCycloneDXBom([]);
    const new_ = makeCycloneDXBom([cycloneDXComponentA]);
    const result = diffSbom(old, new_);
    const formatted = formatDiffResult(result);

    // Purl is shown in the "Added" section
    assert.ok(formatted.includes("pkg:npm/lodash@4.17.21"));
  });

  it("should handle empty diff (no changes)", () => {
    const old = makeCycloneDXBom([]);
    const new_ = makeCycloneDXBom([]);
    const result = diffSbom(old, new_);
    const formatted = formatDiffResult(result);

    assert.ok(formatted.includes("SBOM Diff Report"));
    assert.ok(formatted.includes("Added:     0"));
    assert.ok(formatted.includes("Removed:   0"));
    assert.ok(formatted.includes("Updated:   0"));
    assert.ok(formatted.includes("Unchanged: 0"));
  });

  it("should show metadata in formatted output", () => {
    const doc = makeCycloneDXBom([]);
    const result = diffSbom(doc, doc);
    const formatted = formatDiffResult(result);

    assert.ok(formatted.includes("Compared at:"));
    assert.ok(formatted.includes("Old format:  cyclonedx"));
    assert.ok(formatted.includes("New format:  cyclonedx"));
  });

  it("should show total count in summary", () => {
    const old = makeCycloneDXBom([cycloneDXComponentA, cycloneDXComponentB]);
    const new_ = makeCycloneDXBom([cycloneDXComponentA, cycloneDXComponentB]);
    const result = diffSbom(old, new_);
    const formatted = formatDiffResult(result);

    assert.ok(formatted.includes("Total:     2"));
  });
});

// ============================================================================
// Tests: Large SBOM Performance
// ============================================================================

describe("diffSbom - Performance", () => {
  it("should handle large SBOMs efficiently", () => {
    const count = 1000;
    const oldComponents: CycloneDXComponent[] = [];
    const newComponents: CycloneDXComponent[] = [];

    for (let i = 0; i < count; i++) {
      const name = `package-${String(i).padStart(4, "0")}`;
      oldComponents.push({
        type: "library",
        "bom-ref": `pkg:npm/${name}@1.0.0`,
        name,
        version: "1.0.0",
        purl: `pkg:npm/${name}@1.0.0`,
      });
      // New version: half unchanged, half updated
      newComponents.push({
        type: "library",
        "bom-ref": `pkg:npm/${name}@${i % 2 === 0 ? "1.0.0" : "2.0.0"}`,
        name,
        version: i % 2 === 0 ? "1.0.0" : "2.0.0",
        purl: `pkg:npm/${name}@${i % 2 === 0 ? "1.0.0" : "2.0.0"}`,
      });
    }

    // Add 50 new packages to new
    for (let i = count; i < count + 50; i++) {
      const name = `new-package-${i}`;
      newComponents.push({
        type: "library",
        "bom-ref": `pkg:npm/${name}@1.0.0`,
        name,
        version: "1.0.0",
        purl: `pkg:npm/${name}@1.0.0`,
      });
    }

    // Add 50 removed packages (in old but not in new)
    for (let i = count; i < count + 50; i++) {
      const name = `old-package-${i}`;
      oldComponents.push({
        type: "library",
        "bom-ref": `pkg:npm/${name}@1.0.0`,
        name,
        version: "1.0.0",
        purl: `pkg:npm/${name}@1.0.0`,
      });
    }

    const old = makeCycloneDXBom(oldComponents);
    const new_ = makeCycloneDXBom(newComponents);

    const startTime = Date.now();
    const result = diffSbom(old, new_);
    const elapsed = Date.now() - startTime;

    // Should complete within reasonable time (generous for CI)
    assert.ok(elapsed < 5000, `Diff took ${elapsed}ms, expected < 5000ms`);

    assert.equal(result.summary.totalUnchanged, 500);  // Half of 1000
    assert.equal(result.summary.totalUpdated, 500);     // Other half
    assert.equal(result.summary.totalAdded, 50);        // New packages
    assert.equal(result.summary.totalRemoved, 50);      // Old packages
  });
});

// ============================================================================
// Tests: Scoped Packages
// ============================================================================

describe("diffSbom - Scoped Packages", () => {
  it("should handle scoped packages correctly", () => {
    const old = makeCycloneDXBom([]);
    const new_ = makeCycloneDXBom([cycloneDXComponentScoped]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalAdded, 1);
    assert.equal(result.added[0].name, "@scope/package");
    assert.equal(result.added[0].group, "@scope");
    assert.equal(result.added[0].version, "2.0.0");
  });

  it("should track scoped package updates", () => {
    const oldComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/%40scope%2Fpackage@1.0.0",
      name: "@scope/package",
      version: "1.0.0",
      purl: "pkg:npm/%40scope%2Fpackage@1.0.0",
    };
    const newComp: CycloneDXComponent = {
      type: "library",
      "bom-ref": "pkg:npm/%40scope%2Fpackage@2.0.0",
      name: "@scope/package",
      version: "2.0.0",
      purl: "pkg:npm/%40scope%2Fpackage@2.0.0",
    };

    const old = makeCycloneDXBom([oldComp]);
    const new_ = makeCycloneDXBom([newComp]);
    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUpdated, 1);
    assert.equal(result.updated[0].name, "@scope/package");
    assert.equal(result.updated[0].previousVersion, "1.0.0");
    assert.equal(result.updated[0].version, "2.0.0");
  });
});

// ============================================================================
// Tests: SWID format detection
// ============================================================================

describe("diffSbom - SWID format", () => {
  it("should detect SWID format and extract tags", () => {
    const oldTag = {
      tagId: "com.example.old-software",
      softwareIdentificationScheme: "swid",
      name: "old-software",
      tagVersion: "1.0.0",
    };
    const newTag = {
      tagId: "com.example.new-software",
      softwareIdentificationScheme: "swid",
      name: "new-software",
      tagVersion: "2.0.0",
    };

    const result = diffSbom(oldTag, newTag);

    assert.equal(result.metadata.oldFormat, "swid");
    assert.equal(result.metadata.newFormat, "swid");
    assert.equal(result.summary.totalAdded, 1);
    assert.equal(result.summary.totalRemoved, 1);
    assert.equal(result.added[0].name, "new-software");
    assert.equal(result.removed[0].name, "old-software");
  });

  it("should handle SWID tag set format", () => {
    const old = { tags: [{ tagId: "a", name: "pkg-a", tagVersion: "1.0", softwareIdentificationScheme: "swid" }] };
    const new_ = { tags: [{ tagId: "a", name: "pkg-a", tagVersion: "1.0", softwareIdentificationScheme: "swid" }] };

    const result = diffSbom(old, new_);

    assert.equal(result.summary.totalUnchanged, 1);
  });
});
