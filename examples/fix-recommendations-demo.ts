/**
 * Demo: Fix Recommendations in CycloneDX SBOM Output
 *
 * This example demonstrates how fix recommendations are included
 * in CycloneDX vulnerability data.
 */

import { generateCycloneDX } from "../src/sbom/cyclonedx-generator";
import { serializeCycloneDXToXml } from "../src/sbom/cyclonedx-generator";
import type { VulnerabilityFinding } from "../src/types";
import type { SbomComponent, ComponentVulnerabilityMap } from "../src/sbom/types";

// Sample components
const components: SbomComponent[] = [
  {
    name: "express",
    version: "4.17.1",
    purl: "pkg:npm/express@4.17.1",
  },
  {
    name: "lodash",
    version: "4.17.20",
    purl: "pkg:npm/lodash@4.17.20",
  },
];

// Sample vulnerabilities with fix information
const vulnerabilities: VulnerabilityFinding[] = [
  {
    id: "CVE-2021-44906",
    source: "github",
    packageName: "express",
    packageVersion: "4.17.1",
    severity: "medium",
    title: "Open Redirect in express",
    fixedVersion: "4.17.3",
    cvssScore: 6.1,
    publishedAt: "2021-03-22T00:00:00Z",
    url: "https://github.com/advisories/GHSA-rvff-897h-2f5p",
  },
  {
    id: "CVE-2020-28500",
    source: "github",
    packageName: "lodash",
    packageVersion: "4.17.20",
    severity: "high",
    title: "ReDoS in lodash",
    fixedVersion: "4.17.21",
    cvssScore: 7.5,
    publishedAt: "2021-04-01T00:00:00Z",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2020-28500",
  },
  {
    id: "CVE-2021-99999",
    source: "nvd",
    packageName: "express",
    packageVersion: "4.17.1",
    severity: "critical",
    title: "Critical vulnerability with no fix yet",
    cvssScore: 9.8,
    publishedAt: "2021-08-10T00:00:00Z",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2021-99999",
  },
];

// Build vulnerability map
const vulnMap: ComponentVulnerabilityMap = new Map();
vulnMap.set("express@4.17.1", vulnerabilities.filter(v => v.packageName === "express"));
vulnMap.set("lodash@4.17.20", vulnerabilities.filter(v => v.packageName === "lodash"));

console.log("=== CycloneDX JSON Output with Fix Recommendations ===\n");

const bom = generateCycloneDX(components, vulnMap, {
  format: "cyclonedx",
  includeVulnerabilities: true,
  projectName: "demo-project",
  projectVersion: "1.0.0",
});

// Show vulnerability recommendations
if (bom.vulnerabilities) {
  console.log("Vulnerabilities with Fix Recommendations:\n");
  
  for (const vuln of bom.vulnerabilities) {
    console.log(`Vulnerability: ${vuln.id}`);
    console.log(`  Package: ${vuln.affects[0]?.ref}`);
    console.log(`  Fix Available: ${vuln.fixAvailable}`);
    
    if (vuln.fixAvailable && vuln.fixVersions) {
      console.log(`  Fix Versions: ${vuln.fixVersions.join(', ')}`);
    }
    
    console.log(`  Recommendation: ${vuln.recommendation}`);
    
    if (vuln.upgradePath) {
      console.log(`  Upgrade Path: ${vuln.upgradePath}`);
    }
    console.log();
  }
}

console.log("\n=== CycloneDX XML Output with Fix Recommendations ===\n");

const xml = serializeCycloneDXToXml(bom);

// Show a snippet of the XML with fix recommendations
const lines = xml.split('\n');
const vulnStart = lines.findIndex(line => line.includes('<vulnerability>'));
const vulnEnd = lines.findIndex((line, idx) => idx > vulnStart && line.includes('</vulnerability>'));

if (vulnStart !== -1 && vulnEnd !== -1) {
  // Show first vulnerability in XML
  const vulnLines = lines.slice(vulnStart, vulnEnd + 1);
  console.log("First vulnerability in XML format:");
  console.log(vulnLines.join('\n'));
}
