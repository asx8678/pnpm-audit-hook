import type { PackageRef } from "../types";
import { npmPurl } from "../utils/semver";
import { parseSubresourceIntegrity } from "../utils/hash";

export interface SbomOptions {
  format: "cyclonedx" | "spdx";
  toolVersion?: string;
  dependencies?: Record<string, string[]>; // key = name@version
}

export function toCycloneDxJson(pkgs: PackageRef[], opts: SbomOptions): any {
  const components = pkgs.map((p) => {
    const purl = npmPurl(p.name, p.version);

    const hashes: Array<{ alg: string; content: string }> = [];
    if (p.integrity) {
      const sri = parseSubresourceIntegrity(p.integrity);
      if (sri)
        hashes.push({
          alg: sri.algorithm.toUpperCase(),
          content: sri.digestBase64,
        });
    }

    return {
      type: "library",
      name: p.name,
      version: p.version,
      purl,
      hashes: hashes.length ? hashes : undefined,
    };
  });

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
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "org",
          name: "pnpm-audit-hook",
          version: opts.toolVersion ?? "1.0.0",
        },
      ],
    },
    components,
    dependencies: dependencies.length ? dependencies : undefined,
  };
}

export function toSpdxJson(pkgs: PackageRef[], opts: SbomOptions): any {
  // Minimal SPDX 2.3 document.
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
    name: "pnpm-audit-hook SBOM",
    documentNamespace: `https://example.org/spdx/${Date.now()}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators: [`Tool: pnpm-audit-hook@${opts.toolVersion ?? "1.0.0"}`],
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
