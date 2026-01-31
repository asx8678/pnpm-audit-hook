# Static Vulnerability Database

This directory contains the pre-built static vulnerability database for pnpm-audit-hook.

## Overview

The static database provides fast, offline lookup of npm package vulnerabilities from the GitHub Advisory Database. It serves as a baseline for historical vulnerabilities, reducing API calls and improving performance.

## Contents

- `index.json` - Database metadata and package index
- `packages/` - Individual JSON files for each vulnerable package

## Current Status

- **Last Updated**: See `index.json`
- **Cutoff Date**: See `index.json`
- **Totals**: See `index.json`
- **Data Source**: GitHub Advisory Database

## Data Schema

### index.json

```json
{
  "schemaVersion": 1,
  "lastUpdated": "ISO date string",
  "cutoffDate": "ISO date string",
  "totalVulnerabilities": number,
  "totalPackages": number,
  "packages": {
    "package-name": {
      "count": number,
      "latestVuln": "ISO date string",
      "maxSeverity": "critical|high|medium|low|unknown"
    }
  },
  "buildInfo": {
    "generator": "string",
    "sources": ["github-advisory"],
    "durationMs": number
  }
}
```

Legacy index files may use `vulnCount` and `lastModified` instead of
`count`/`latestVuln`. The reader normalizes both formats at runtime.

### packages/{name}.json

```json
{
  "packageName": "package-name",
  "lastUpdated": "ISO date string",
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "title": "Vulnerability title",
      "description": "Description (truncated to 500 chars)",
      "severity": "critical|high|medium|low|unknown",
      "url": "https://github.com/advisories/...",
      "publishedAt": "ISO date string",
      "modifiedAt": "ISO date string",
      "source": "github",
      "identifiers": [
        { "type": "GHSA", "value": "GHSA-xxxx" },
        { "type": "CVE", "value": "CVE-2021-xxxx" }
      ],
      "affectedVersions": [
        { "range": "semver range (e.g., '<4.17.21')", "fixed": "4.17.21" }
      ]
    }
  ]
}
```

Note: Older datasets may use `name` instead of `packageName`, and flatten
`affectedVersions` into `affectedRange` + `fixedVersion`. The reader supports
both formats for backward compatibility.

## Regenerating the Database

### Full Rebuild (Recommended with GITHUB_TOKEN)

```bash
# Set GitHub token for higher rate limits (5000/hour vs 60/hour)
export GITHUB_TOKEN=your_github_personal_access_token

# Full rebuild from GitHub Advisory Database
npm run update-vuln-db
```

### Sample Data Only (No API calls)

```bash
# Generate sample data for ~50 popular packages
npm run update-vuln-db -- --sample
```

### Incremental Update

```bash
# Update only advisories changed since last update
npm run update-vuln-db:incremental
```

### Custom Cutoff Date

```bash
# Set a specific cutoff date
npm run update-vuln-db -- --cutoff=2024-06-30T23:59:59Z
```

## Rate Limits

Without a GitHub token:
- 60 requests/hour
- ~6000 advisories can be fetched per hour (100 per request)
- Full database may take multiple hours

With a GitHub Personal Access Token:
- 5000 requests/hour
- Full database can be built in a few minutes
- Token needs no special scopes (public data only)

## Included Packages (Sample Dataset)

The sample dataset includes well-known vulnerable packages:

- lodash (4 vulnerabilities)
- axios (2 vulnerabilities)
- express (1 vulnerability)
- minimist (2 vulnerabilities)
- tar (2 vulnerabilities)
- handlebars (2 vulnerabilities)
- node-forge (2 vulnerabilities)
- follow-redirects (2 vulnerabilities)
- And 37 more...

## Notes

- Scoped packages use `__` instead of `/` in filenames (e.g., `@babel/core` becomes `@babel__core.json`)
- Descriptions are truncated to 500 characters to keep file sizes reasonable
- The database includes vulnerabilities from 2019-2025
- For the most current vulnerability data, the live GitHub Advisory API is used in parallel
