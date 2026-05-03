/**
 * SWID Tags generator (ISO/IEC 19770-2:2015).
 *
 * Generates Software Identification (SWID) Tags from audit results.
 * SWID Tags are an international standard for identifying installed software,
 * commonly used for enterprise compliance and asset management.
 *
 * @module sbom/swid-generator
 *
 * @see {@link https://www.iso.org/standard/65666.html} - ISO/IEC 19770-2:2015
 * @see {@link https://tagvault.org/} - TagVault.org (SWID Tag repository)
 */

import type { VulnerabilityFinding } from "../types";
import type {
  SbomComponent,
  SbomOptions,
  SbomResult,
  SwidOptions,
  SwidTag,
  SwidTagSet,
  SwidEntity,
  SwidLink,
  ComponentVulnerabilityMap,
} from "./types";

/** Default SWID configuration */
const DEFAULT_SWID_OPTIONS: Required<SwidOptions> = {
  regid: "com.pnpm-audit-hook.pnpm-project",
  softwareIdentificationScheme: "swid",
  tagVersion: "1.0",
  structure: "single",
  addOn: false,
  softwareCreator: {
    name: "pnpm-audit-hook",
    regid: "com.pnpm-audit-hook",
  },
  softwareLicensor: {
    name: "pnpm-audit-hook",
    regid: "com.pnpm-audit-hook",
  },
};

/** Tool metadata */
const TOOL_VERSION = "1.4.3";

/**
 * Generate a unique SWID Tag ID (tagId).
 * Format: UUID v4 to ensure global uniqueness per ISO/IEC 19770-2.
 *
 * @returns UUID v4 string
 */
function generateTagId(): string {
  try {
    const crypto = require("node:crypto");
    return crypto.randomUUID();
  } catch {
    // Fallback for older Node.js
    return `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.replace(/[xy]/g, (c: string) => {
      const r = (Math.random() * 16) | 0;
      const v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }
}

/**
 * Generate a SWID Tag ID for a package.
 * Uses a deterministic format: sha256(packageName@version) truncated to 16 chars.
 *
 * @param name - Package name
 * @param version - Package version
 * @returns Deterministic tagId
 */
function generatePackageTagId(name: string, version: string): string {
  try {
    const crypto = require("node:crypto");
    const hash = crypto
      .createHash("sha256")
      .update(`${name}@${version}`)
      .digest("hex")
      .slice(0, 16);

    // Format as UUID-like string for readability
    return [
      hash.slice(0, 8),
      hash.slice(8, 12),
      `4${hash.slice(13, 16)}`,
      `8${hash.slice(17, 20)}`,
      hash.slice(20, 32),
    ].join("-");
  } catch {
    return generateTagId();
  }
}

/**
 * Sanitize a package name for use in SWID Tag identifiers.
 *
 * @param name - Package name to sanitize
 * @returns Sanitized name
 */
function sanitizeName(name: string): string {
  return name
    .replace(/^@/, "") // Remove leading scope marker
    .replace(/[/\\]/g, "-") // Replace slashes with dashes
    .replace(/[^A-Za-z0-9.\-]/g, "-") // Replace invalid chars
    .replace(/-+/g, "-") // Collapse multiple dashes
    .replace(/^-|-$/g, ""); // Trim leading/trailing dashes
}

/**
 * Escape XML special characters.
 *
 * @param text - Text to escape
 * @returns Escaped XML text
 */
function escapeXml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Convert a component to a SWID Tag.
 *
 * @param component - SBOM component
 * @param options - SWID generation options
 * @param index - Component index (for deterministic IDs)
 * @returns SWID Tag structure
 */
function toSwidTag(
  component: SbomComponent,
  options: Required<SwidOptions>,
  index: number,
): SwidTag {
  const tagId = generatePackageTagId(component.name, component.version);
  const regid = `${options.regid}.${sanitizeName(component.name)}`;

  const tag: SwidTag = {
    tagId,
    regid,
    name: component.name,
    tagVersion: options.tagVersion,
    softwareIdentificationScheme: options.softwareIdentificationScheme,
    addOn: options.addOn,
    structure: options.structure,
    entities: [],
  };

  // Add meta information
  tag.meta = {
    product: component.name,
    vendor: component.repository ? new URL(component.repository).hostname : undefined,
    version: component.version,
    versionScheme: "semver",
    date: new Date().toISOString(),
  };

  // Add software entity (required by ISO/IEC 19770-2)
  tag.entities.push({
    name: component.name,
    regid: options.regid,
    role: "software",
  });

  // Add tag creator entity (required by ISO/IEC 19770-2)
  tag.entities.push({
    name: options.softwareCreator.name,
    regid: options.softwareCreator.regid,
    role: "tagCreator",
  });

  // Add software creator if provided
  if (component.repository) {
    try {
      const repoUrl = new URL(component.repository);
      tag.entities.push({
        name: repoUrl.hostname,
        role: "softwareCreator",
      });
    } catch {
      // Invalid URL, skip
    }
  }

  // Add software licensor if provided
  if (options.softwareLicensor) {
    tag.entities.push({
      name: options.softwareLicensor.name,
      regid: options.softwareLicensor.regid,
      role: "softwareLicensor",
    });
  }

  // Add links
  const links: SwidLink[] = [];

  if (component.homepage) {
    links.push({ href: component.homepage, rel: "seeAlso" });
  }

  if (component.repository) {
    links.push({ href: component.repository, rel: "package" });
  }

  if (links.length > 0) {
    tag.links = links;
  }

  return tag;
}

/**
 * Generate SWID Tags for all components.
 *
 * @param components - Array of SBOM components
 * @param options - SWID generation options
 * @returns SWID Tag Set containing all tags
 */
export function generateSwidTags(
  components: SbomComponent[],
  options: SwidOptions = {},
): SwidTagSet {
  const mergedOptions: Required<SwidOptions> = {
    ...DEFAULT_SWID_OPTIONS,
    ...options,
    softwareCreator: {
      ...DEFAULT_SWID_OPTIONS.softwareCreator,
      ...options.softwareCreator,
    },
    softwareLicensor: {
      ...DEFAULT_SWID_OPTIONS.softwareLicensor,
      ...options.softwareLicensor,
    },
  };

  const tags = components.map((cmp, idx) =>
    toSwidTag(cmp, mergedOptions, idx),
  );

  return { tags };
}

/**
 * Serialize a SWID Tag to ISO/IEC 19770-2:2015 compliant XML.
 *
 * @param tag - SWID Tag to serialize
 * @returns XML string
 */
export function serializeSwidTagToXml(tag: SwidTag): string {
  const lines: string[] = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<swid>",
    `  <tagId>${escapeXml(tag.tagId)}</tagId>`,
    `  <regid>${escapeXml(tag.regid)}</regid>`,
    `  <name>${escapeXml(tag.name)}</name>`,
    `  <tagVersion>${escapeXml(tag.tagVersion)}</tagVersion>`,
    `  <softwareIdentificationScheme>${escapeXml(tag.softwareIdentificationScheme)}</softwareIdentificationScheme>`,
  ];

  // Add optional fields
  if (tag.csi) {
    lines.push(`  <csi>${escapeXml(tag.csi)}</csi>`);
  }

  if (tag.summary) {
    lines.push(`  <summary>${escapeXml(tag.summary)}</summary>`);
  }

  lines.push(`  <addOn>${tag.addOn ? "true" : "false"}</addOn>`);
  if (tag.structure) {
    lines.push(`  <structure>${escapeXml(tag.structure)}</structure>`);
  }

  // Add meta section
  if (tag.meta) {
    lines.push("  <meta>");
    lines.push(`    <product>${escapeXml(tag.meta.product)}</product>`);
    if (tag.meta.vendor) {
      lines.push(`    <vendor>${escapeXml(tag.meta.vendor)}</vendor>`);
    }
    if (tag.meta.version) {
      lines.push(`    <version>${escapeXml(tag.meta.version)}</version>`);
    }
    if (tag.meta.versionScheme) {
      lines.push(`    <versionScheme>${escapeXml(tag.meta.versionScheme)}</versionScheme>`);
    }
    if (tag.meta.date) {
      lines.push(`    <date>${escapeXml(tag.meta.date)}</date>`);
    }
    lines.push("  </meta>");
  }

  // Add entities
  for (const entity of tag.entities) {
    lines.push("  <entity>");
    lines.push(`    <name>${escapeXml(entity.name)}</name>`);
    if (entity.regid) {
      lines.push(`    <regid>${escapeXml(entity.regid)}</regid>`);
    }
    lines.push(`    <role>${escapeXml(entity.role)}</role>`);
    lines.push("  </entity>");
  }

  // Add links
  if (tag.links && tag.links.length > 0) {
    for (const link of tag.links) {
      lines.push(`  <link href="${escapeXml(link.href)}" rel="${escapeXml(link.rel)}" />`);
    }
  }

  lines.push("</swid>");
  return lines.join("\n");
}

/**
 * Serialize a SWID Tag Set to ISO/IEC 19770-2:2015 compliant XML.
 *
 * @param tagSet - SWID Tag Set to serialize
 * @returns XML string with wrapper element
 */
export function serializeSwidTagSetToXml(tagSet: SwidTagSet): string {
  const lines: string[] = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<swidTagSet>",
  ];

  for (const tag of tagSet.tags) {
    // Generate the tag XML without the XML declaration
    const tagXml = serializeSwidTagToXml(tag)
      .split("\n")
      .filter((line) => !line.startsWith('<?xml')) // Remove XML declaration from each tag
      .map((line) => `  ${line}`)
      .join("\n");
    lines.push(tagXml);
  }

  lines.push("</swidTagSet>");
  return lines.join("\n");
}

/**
 * Generate SWID SBOM and format as XML string.
 *
 * @param components - Array of SBOM components with package info
 * @param vulnMap - Component vulnerability map
 * @param options - SBOM generation options
 * @returns SBOM generation result with XML content
 */
export function generateSwidSbom(
  components: SbomComponent[],
  vulnMap: ComponentVulnerabilityMap,
  options: SbomOptions,
): SbomResult {
  const startTime = Date.now();

  // Merge SWID options from SBOM options
  const swidOptions: SwidOptions = {
    ...options.swidOptions,
    regid: options.swidOptions?.regid ?? `com.pnpm-audit-hook.${options.projectName ?? "project"}`,
  };

  // Generate tags
  const tagSet = generateSwidTags(components, swidOptions);

  // Serialize to XML
  const content = serializeSwidTagSetToXml(tagSet);

  // Count vulnerabilities
  let vulnerabilityCount = 0;
  for (const component of components) {
    const pkgKey = `${component.name}@${component.version}`;
    const findings = vulnMap.get(pkgKey) ?? [];
    vulnerabilityCount += findings.length;
  }

  return {
    content,
    format: "swid",
    componentCount: components.length,
    vulnerabilityCount,
    outputPath: options.outputPath,
    durationMs: Date.now() - startTime,
  };
}
