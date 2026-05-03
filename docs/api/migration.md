# Migration Guide

> Guide for upgrading between pnpm-audit-hook versions.

## Table of Contents

- [Version Compatibility](#version-compatibility)
- [Upgrading to v1.4.x](#upgrading-to-v14x)
- [Upgrading to v1.3.x](#upgrading-to-v13x)
- [Breaking Changes](#breaking-changes)
- [Configuration Changes](#configuration-changes)

---

## Version Compatibility

| Version | Node.js | pnpm | TypeScript |
|---------|---------|------|------------|
| 1.4.x | ≥18.0 | ≥8.0 | ≥5.0 |
| 1.3.x | ≥18.0 | ≥8.0 | ≥5.0 |
| 1.2.x | ≥16.0 | ≥7.0 | ≥4.7 |

---

## Upgrading to v1.4.x

### Changes in v1.4.3

#### New Features

- **Dependency Chain Analysis** — Vulnerabilities now include chain context
- **Risk Scoring** — CVSS-based risk assessment with composite scores
- **Transitive Severity Override** — Option to downgrade severity for transitive deps

#### Configuration Additions

```yaml
# New in v1.4.x
policy:
  transitiveSeverityOverride: downgrade-by-one  # New option
```

#### No Breaking Changes

This is a backwards-compatible release. No migration steps required.

---

### Changes in v1.4.0

#### New Features

- **Static Vulnerability Database** — Bundled offline vulnerability data
- **Cache Auto-Prune** — Automatic cleanup of expired cache entries
- **Enhanced Security** — Path traversal and malicious content detection

#### Configuration Additions

```yaml
# New in v1.4.x
staticBaseline:
  enabled: true
  cutoffDate: "2025-01-01"
  dataPath: "./custom-static-db"  # Optional
```

#### Migration Steps

1. **No action required** — Default configuration works automatically
2. **Optional: Configure static baseline**

```yaml
# .pnpm-audit.yaml
staticBaseline:
  enabled: true  # Default: true
```

3. **Optional: Adjust cutoff date**

```yaml
staticBaseline:
  cutoffDate: "2024-06-01"  # Use custom cutoff
```

---

## Upgrading to v1.3.x

### Changes in v1.3.0

#### New Features

- **Multiple Vulnerability Sources** — GitHub, NVD, and OSV
- **Structured Output** — JSON and table output formats
- **CI/CD Annotations** — GitHub Actions, Azure DevOps, AWS CodeBuild

#### Configuration Changes

The `sources` configuration was expanded:

```yaml
# Before (v1.2.x)
sources:
  enabled: true

# After (v1.3.x)
sources:
  github:
    enabled: true
  nvd:
    enabled: true
  osv:
    enabled: true
```

#### Migration Steps

1. **Update config file**

```yaml
# .pnpm-audit.yaml
# Replace old format
sources:
  github: { enabled: true }
  nvd: { enabled: true }
  osv: { enabled: true }
```

2. **Update environment variables**

```bash
# Old (deprecated)
PNPM_AUDIT_SOURCES=true

# New
PNPM_AUDIT_FAIL_ON_NO_SOURCES=true
PNPM_AUDIT_FAIL_ON_SOURCE_ERROR=true
```

3. **Update CI/CD pipelines**

```yaml
# Add source error handling
- name: Audit
  run: pnpm audit
  env:
    PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: 'true'
```

---

## Breaking Changes

### v1.4.0

**None** — This release is backwards-compatible.

### v1.3.0

#### Source Configuration Format

**Before:**
```yaml
sources:
  enabled: true
```

**After:**
```yaml
sources:
  github: { enabled: true }
  nvd: { enabled: true }
  osv: { enabled: true }
```

#### Exit Code Changes

| Code | v1.2.x | v1.3.x+ |
|------|--------|---------|
| 3 | N/A | Source error (new) |

### v1.2.0

**Initial stable release** — No previous versions to migrate from.

---

## Configuration Changes

### Policy Configuration

#### v1.4.x Additions

```yaml
policy:
  # Existing
  block: [critical, high]
  warn: [medium, low, unknown]
  allowlist: []

  # New in v1.4.x
  transitiveSeverityOverride: downgrade-by-one
```

#### Severity Values

The following severity values are supported across all versions:

| Value | Description |
|-------|-------------|
| `critical` | Exploitable with severe impact |
| `high` | Exploitable with significant impact |
| `medium` | Moderate impact or limited exploitability |
| `low` | Minimal impact |
| `unknown` | Could not be determined |

### Source Configuration

#### v1.3.x+ Format

```yaml
sources:
  github:
    enabled: true  # GitHub Advisory Database
  nvd:
    enabled: true  # National Vulnerability Database
  osv:
    enabled: true  # Open Source Vulnerabilities
```

### Performance Configuration

No changes across versions.

```yaml
performance:
  timeoutMs: 15000  # Max: 300000 (5 minutes)
```

### Cache Configuration

No changes across versions.

```yaml
cache:
  ttlSeconds: 3600  # Max: 86400 (24 hours)
```

---

## Environment Variables

### Deprecated Variables

| Variable | Deprecated In | Replacement |
|----------|---------------|-------------|
| `PNPM_AUDIT_SOURCES` | v1.3.0 | `PNPM_AUDIT_FAIL_ON_NO_SOURCES` |

### Current Variables

| Variable | Added In | Description |
|----------|----------|-------------|
| `PNPM_AUDIT_CONFIG_PATH` | v1.2.0 | Custom config path |
| `PNPM_AUDIT_BLOCK_SEVERITY` | v1.2.0 | Override block severities |
| `PNPM_AUDIT_FAIL_ON_NO_SOURCES` | v1.3.0 | Fail when all sources disabled |
| `PNPM_AUDIT_FAIL_ON_SOURCE_ERROR` | v1.3.0 | Fail on source errors |
| `PNPM_AUDIT_OFFLINE` | v1.4.0 | Offline mode |

---

## Upgrade Checklist

### v1.2.x → v1.3.x

- [ ] Update `sources` configuration to new format
- [ ] Replace `PNPM_AUDIT_SOURCES` with new env vars
- [ ] Test CI/CD pipelines with new exit codes
- [ ] Update any custom scripts checking exit codes

### v1.3.x → v1.4.x

- [ ] No required changes (backwards-compatible)
- [ ] Optional: Configure `staticBaseline`
- [ ] Optional: Enable `transitiveSeverityOverride`
- [ ] Review new dependency chain analysis in results

---

## Troubleshooting Upgrades

### "Unrecognized config key" Warning

If you see warnings about unrecognized keys after upgrading:

```
Unrecognized config key "sources" — did you mean ...?
```

This means your config file uses an old format. Update to the new format:

```yaml
# Old
sources:
  enabled: true

# New
sources:
  github: { enabled: true }
  nvd: { enabled: true }
  osv: { enabled: true }
```

### Source Errors After Upgrade

If you see source errors after upgrading to v1.3.x:

```
Source failure: nvd: timeout
```

This is expected if NVD is slow or unavailable. Options:

1. Disable NVD: `nvd: { enabled: false }`
2. Increase timeout: `performance: { timeoutMs: 30000 }`
3. Allow source errors: `failOnSourceError: false`

### Static Baseline Issues

If the static baseline causes issues:

```yaml
# Disable static baseline
staticBaseline:
  enabled: false
```

---

## Rollback

If you need to rollback to a previous version:

1. **Install previous version**

```bash
npm install pnpm-audit-hook@1.3.0
# or
pnpm add pnpm-audit-hook@1.3.0
```

2. **Restore old configuration**

```yaml
# Restore v1.2.x format if needed
sources:
  enabled: true
```

3. **Revert environment variables**

```bash
# Restore old env vars
unset PNPM_AUDIT_FAIL_ON_NO_SOURCES
unset PNPM_AUDIT_FAIL_ON_SOURCE_ERROR
unset PNPM_AUDIT_OFFLINE
```

---

## Support

If you encounter issues during migration:

1. Check the [Troubleshooting Guide](../troubleshooting.md)
2. Review [Configuration Documentation](./config.md)
3. Open an issue on [GitHub](https://github.com/asx8678/pnpm-audit-hook/issues)
