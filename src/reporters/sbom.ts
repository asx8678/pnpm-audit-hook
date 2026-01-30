import type { PackageRef } from "../types";
import { npmPurl } from "../utils/semver";
import { parseSubresourceIntegrity } from "../utils/hash";

export interface SbomOptions {
  format: "cyclonedx" | "spdx";
  toolVersion?: string;
  dependencies?: Record<string, string[]>; // key = name@version
}

const DEFAULT_TOOL_VERSION = "1.0.0";
const TOOL_NAME = "pnpm-audit-hook";

function buildHash(integrity?: string) {
  if (!integrity) return undefined;
  const sri = parseSubresourceIntegrity(integrity);
  if (!sri) return undefined;
  return [{ alg: sri.algorithm.toUpperCase(), content: sri.digestBase64 }];
}

export function toCycloneDxJson(pkgs: PackageRef[], opts: SbomOptions): any {
  const timestamp = new Date().toISOString();
  const toolVersion = opts.toolVersion ?? DEFAULT_TOOL_VERSION;

  const components = pkgs.map((p) => ({
    type: "library",
    name: p.name,
    version: p.version,
    purl: npmPurl(p.name, p.version),
    hashes: buildHash(p.integrity),
  }));

  const depMap = opts.dependencies ?? {};
  const dependencies = Object.entries(depMap).map(([k, deps]) => {
    const [name, version] = splitNameVersion(k);
    return {
      ref: npmPurl(name, version),
      dependsOn: deps.map((d) => {
        const [dn, dv] = splitNameVersion(d);
        return npmPurl(dn, dv);
      }),
    };
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: "org", name: TOOL_NAME, version: toolVersion }],
    },
    components,
    dependencies: dependencies.length ? dependencies : undefined,
  };
}

export function toSpdxJson(pkgs: PackageRef[], opts: SbomOptions): any {
  const timestamp = new Date().toISOString();
  const toolVersion = opts.toolVersion ?? DEFAULT_TOOL_VERSION;

  const packages = pkgs.map((p, idx) => ({
    SPDXID: `SPDXRef-Package-${idx + 1}`,
    name: p.name,
    versionInfo: p.version,
    downloadLocation: p.tarball ?? "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    supplier: "NOASSERTION",
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: npmPurl(p.name, p.version),
      },
    ],
  }));

  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${TOOL_NAME} SBOM`,
    documentNamespace: `https://example.org/spdx/${Date.now()}`,
    creationInfo: {
      created: timestamp,
      creators: [`Tool: ${TOOL_NAME}@${toolVersion}`],
    },
    packages,
    relationships: [],
  };
}

function splitNameVersion(key: string): [string, string] {
  // key is "name@version" (scoped package names contain '@', so split from last '@')
  const idx = key.lastIndexOf("@");
  if (idx <= 0) return [key, ""];
  return [key.slice(0, idx), key.slice(idx + 1)];
}
