# Static Vulnerability Database Schema

This document describes the schema and file organization for the static vulnerability database, which stores historical npm vulnerabilities (2020-2025) for offline/cached lookups.

## Design Goals

1. **Fast O(1) Package Lookup**: Index file enables instant check if a package has known vulnerabilities
2. **Efficient Semver Matching**: Pre-computed affected version ranges for quick version checking
3. **Minimal Storage**: Package-based sharding prevents loading unnecessary data
4. **Date Filtering**: Published timestamps enable cutoff-based filtering
5. **Compatibility**: Seamless conversion to existing `VulnerabilityFinding` type

## File Organization

```
src/static-db/
  types.ts              # TypeScript interfaces
  README.md             # This file
  data/
    index.json          # Main index with metadata + package listing
    lodash.json         # Vulnerabilities for 'lodash' package
    express.json        # Vulnerabilities for 'express' package
    @babel/
      core.json         # Scoped package: @babel/core
    @angular/
      core.json         # Scoped package: @angular/core
```

### Naming Convention

- **Unscoped packages**: `{package-name}.json` (e.g., `lodash.json`)
- **Scoped packages**: `{scope}/{package}.json` (e.g., `@babel/core.json`)
- Package names are used as-is (no encoding needed for valid npm names)

## Schema Details

### index.json (StaticDbIndex)

The main index file provides O(1) lookup and metadata:

```typescript
{
  // Schema version for forward compatibility
  "schemaVersion": 1,

  // When the database was last built
  "lastUpdated": "2025-01-31T00:00:00Z",

  // Vulnerabilities in this DB were published before this date
  "cutoffDate": "2025-01-01T00:00:00Z",

  // Aggregate statistics
  "totalVulnerabilities": 15420,
  "totalPackages": 3842,

  // O(1) lookup map: package name -> summary info
  "packages": {
    "lodash": {
      "count": 12,           // Number of vulnerabilities
      "latestVuln": "2024-09-15T00:00:00Z",
      "maxSeverity": "critical"
    },
    "@babel/core": {
      "count": 3,
      "latestVuln": "2023-05-22T00:00:00Z",
      "maxSeverity": "high"
    }
  },

  // Build metadata (optional)
  "buildInfo": {
    "generator": "pnpm-audit-hook/build-static-db",
    "sources": ["github-advisory"],
    "durationMs": 45230
  }
}
```

### Package Shard Files (PackageShard)

Each package with vulnerabilities has its own JSON file:

```typescript
{
  // Package name (for validation)
  "packageName": "lodash",

  // When this shard was last updated
  "lastUpdated": "2025-01-31T00:00:00Z",

  // All vulnerabilities, sorted by publishedAt (newest first)
  "vulnerabilities": [
    {
      "id": "CVE-2021-23337",
      "packageName": "lodash",
      "severity": "high",
      "publishedAt": "2021-02-15T13:15:00Z",
      "modifiedAt": "2024-01-15T00:00:00Z",
      "affectedVersions": [
        {
          "range": "<4.17.21",
          "fixed": "4.17.21"
        }
      ],
      "source": "github",
      "title": "Command Injection in lodash",
      "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
      "identifiers": [
        { "type": "CVE", "value": "CVE-2021-23337" },
        { "type": "GHSA", "value": "GHSA-35jh-r3h4-6jhm" }
      ]
    }
  ]
}
```

## Lookup Algorithm

### 1. Check if package has vulnerabilities (O(1))

```typescript
const index = await db.getIndex();
const hasVulns = packageName in index.packages;
```

### 2. Load package shard (lazy, on-demand)

```typescript
if (hasVulns) {
  const shard = await loadShard(packageName); // Loads lodash.json
}
```

### 3. Filter by version (semver matching)

```typescript
const matching = shard.vulnerabilities.filter(vuln =>
  vuln.affectedVersions.some(av =>
    semver.satisfies(version, av.range)
  )
);
```

### 4. Apply date/severity filters

```typescript
const filtered = matching.filter(vuln =>
  (!options.publishedAfter || vuln.publishedAt >= options.publishedAfter) &&
  (!options.minSeverity || severityLevel(vuln.severity) >= severityLevel(options.minSeverity))
);
```

## Conversion to VulnerabilityFinding

The `StaticVulnerability` type maps directly to `VulnerabilityFinding`:

```typescript
function toFinding(vuln: StaticVulnerability, version: string): VulnerabilityFinding {
  // Combine affected ranges and find first fixed version
  const affectedRange = vuln.affectedVersions.map(v => v.range).join(" || ");
  const fixedVersion = vuln.affectedVersions.find(v => v.fixed)?.fixed;

  return {
    id: vuln.id,
    source: vuln.source,
    packageName: vuln.packageName,
    packageVersion: version,
    title: vuln.title,
    url: vuln.url,
    description: vuln.description,
    severity: vuln.severity,
    publishedAt: vuln.publishedAt,
    modifiedAt: vuln.modifiedAt,
    identifiers: vuln.identifiers,
    affectedRange,
    fixedVersion,
  };
}
```

## Storage Efficiency

### Sharding Benefits

- **Selective loading**: Only load data for packages actually in lockfile
- **Parallel fetching**: Load multiple shards concurrently
- **Cache-friendly**: Each shard can be cached independently

### Index Benefits

- **O(1) existence check**: Instantly know if a package has vulnerabilities
- **Pre-computed metadata**: `maxSeverity` enables quick severity filtering
- **Skip unnecessary I/O**: Don't load shards for clean packages

### Estimated Size

Based on npm ecosystem data (2020-2025):
- ~15,000 total vulnerabilities across ~4,000 packages
- Average shard size: ~2-5 KB (uncompressed JSON)
- Index file: ~200 KB (uncompressed)
- Total database: ~15-20 MB (uncompressed)

## Schema Versioning

The `schemaVersion` field enables forward compatibility:

- Version 1: Initial schema (current)
- Future versions can add optional fields while maintaining backwards compatibility
- Breaking changes increment major version

## Type Definitions

See `src/static-db/types.ts` for complete TypeScript interfaces:

- `AffectedVersionRange` - Version range with optional fixed version
- `StaticVulnerability` - Core vulnerability record
- `StaticPackageData` - Package shard file structure (uses `name` field)
- `PackageShard` - Alias for package data (uses `packageName` field)
- `StaticDbIndex` - Main index with O(1) lookup map
- `PackageIndexEntry` - Summary info per package
- `StaticDatabase` - Runtime query interface
- `StaticDbQueryOptions` - Query filtering options
- `severityLevel()` - Severity comparison helper
- `compareSeverity()` - Compare two severity levels

## Build Process

The database is built from GitHub Advisory data:

1. Fetch all npm advisories via GitHub API
2. Group by package name
3. Generate shard files (one per package)
4. Build index with aggregate statistics
5. Validate schema and semver ranges

Recommended rebuild frequency: Weekly or after major security events.
