# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with `pnpm-audit-hook`. For quick answers to common questions, see the [FAQ section](#faq) below.

## Table of Contents

- [Common Issues](#common-issues)
  - [Installation Issues](#installation-issues)
  - [Configuration Issues](#configuration-issues)
  - [Runtime Issues](#runtime-issues)
  - [CI/CD Issues](#cicd-issues)
- [Error Messages Explained](#error-messages-explained)
- [Configuration Troubleshooting](#configuration-troubleshooting)
- [Diagnostic Tools](#diagnostic-tools)
  - [Health Check Commands](#health-check-commands)
  - [Environment Checks](#environment-checks)
  - [Log Analysis](#log-analysis)
- [FAQ](#faq)
- [Community Resources](#community-resources)

---

## Common Issues

### Installation Issues

#### Issue: `pnpm-audit-scan: command not found`

**Symptoms:**
```bash
$ pnpm-audit-scan
bash: pnpm-audit-scan: command not found
```

**Solutions:**
1. **Check global installation:**
   ```bash
   # Check if installed globally
   pnpm list -g pnpm-audit-hook
   
   # If not installed globally, install it
   pnpm add -g pnpm-audit-hook
   ```

2. **Check PATH:**
   ```bash
   # Ensure pnpm global bin is in PATH
   echo $PATH | grep $(pnpm bin -g)
   
   # Add to PATH if missing (add to ~/.bashrc or ~/.zshrc)
   export PATH="$(pnpm bin -g):$PATH"
   ```

3. **Use npx instead:**
   ```bash
   npx pnpm-audit-scan
   ```

#### Issue: `pnpm install` fails with "pnpmfile not found"

**Symptoms:**
```
Error: Cannot find module './.pnpmfile.cjs'
```

**Solutions:**
1. **Reinstall the hook:**
   ```bash
   pnpm remove pnpm-audit-hook
   pnpm add -D pnpm-audit-hook
   ```

2. **Check .pnpmfile.cjs exists:**
   ```bash
   ls -la .pnpmfile.cjs
   # If missing, create it manually:
   cat > .pnpmfile.cjs << 'EOF'
   module.exports = {
     hooks: {
       readPackage(pkg) {
         return pkg;
       }
     }
   };
   EOF
   ```

3. **Verify pnpm version:**
   ```bash
   pnpm --version  # Should be 8.x or higher
   ```

### Configuration Issues

#### Issue: `Invalid configuration` error

**Symptoms:**
```
Error: Invalid configuration: ...
```

**Solutions:**
1. **Validate YAML syntax:**
   ```bash
   # Check for YAML syntax errors
   node -e "require('yaml').parse(require('fs').readFileSync('.pnpm-audit.yaml', 'utf8'))"
   ```

2. **Use debug mode:**
   ```bash
   PNPM_AUDIT_DEBUG=true pnpm install
   ```

3. **Check for common YAML mistakes:**
   ```yaml
   # ❌ Missing colon
   sources
     github: true
   
   # ✅ Correct
   sources:
     github: true
   ```

#### Issue: Configuration warnings about unknown keys

**Symptoms:**
```
[warn] Unknown configuration key: 'blockSevertiy' - did you mean 'block'?
```

**Solutions:**
1. **Check spelling:** The error message suggests the correct key
2. **Review config schema:**
   ```bash
   # See valid configuration keys
   pnpm-audit-scan --help
   ```

### Runtime Issues

#### Issue: `AUDIT FAILED` blocks installation

**Symptoms:**
```
AUDIT FAILED: Critical vulnerability found in lodash@4.17.21
```

**Solutions:**
1. **One-time bypass:**
   ```bash
   pnpm install --ignore-pnpmfile
   ```

2. **Investigate findings:**
   ```bash
   pnpm-audit-scan --format json | jq '.findings'
   ```

3. **Recommended fixes:**
   - Upgrade vulnerable package to patched version
   - Allowlist false positives in `.pnpm-audit.yaml`
   - Adjust `policy.block` if needed

#### Issue: Slow audits

**Symptoms:**
- Audits take > 30 seconds
- High CPU/network usage

**Solutions:**
1. **Set GitHub token:**
   ```bash
   export GITHUB_TOKEN=your_token_here
   ```

2. **Use offline mode:**
   ```bash
   PNPM_AUDIT_OFFLINE=true pnpm install
   ```

3. **Cache results:**
   ```bash
   # Cache directory is automatically created
   ls -la .pnpm-audit-cache/
   ```

### CI/CD Issues

#### Issue: Verbose logging in CI

**Symptoms:**
- Excessive output in CI logs
- Hard to read build results

**Solutions:**
1. **Suppress verbose output:**
   ```bash
   PNPM_AUDIT_QUIET=true pnpm install
   ```

2. **Use CI-specific format:**
   ```bash
   # For GitHub Actions
   pnpm-audit-scan --format github
   
   # For Azure DevOps
   pnpm-audit-scan --format azure
   ```

#### Issue: Audit fails in CI but works locally

**Symptoms:**
- Works locally, fails in CI
- Different behavior between environments

**Solutions:**
1. **Check environment variables:**
   ```bash
   # Debug environment in CI
   env | grep -i pnpm_audit
   ```

2. **Verify network access:**
   ```bash
   # Test API access
   curl -I https://api.osv.dev/v1/query
   ```

3. **Check Node.js version:**
   ```yaml
   # In CI config
   - uses: actions/setup-node@v4
     with:
       node-version: '18'
   ```

---

## Error Messages Explained

### Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Success | No action needed |
| `1` | Blocked | Review findings and fix/allowlist |
| `2` | Warnings | Review warnings, no block |
| `3` | Source error | Check network/API access |

### Common Error Messages

#### `Failed to read config at .pnpm-audit.yaml: ...`

**Cause:** YAML syntax error or invalid configuration
**Fix:** Validate YAML and check config schema

#### `OSV source failed: ...`

**Cause:** OSV.dev API unreachable or rate limited
**Fix:** 
- Check network connection
- Set `PNPM_AUDIT_OFFLINE=true` for offline mode
- Use GitHub token for higher rate limits

#### `NVD enrichment failed for ... CVE(s)`

**Cause:** NVD API rate limiting or network issues
**Fix:**
- This is usually non-blocking
- Set `failOnSourceError: false` in config if needed

#### `No pnpm-lock.yaml found`

**Cause:** Not in a pnpm project directory
**Fix:**
- Run `pnpm install` first
- Or check current directory

#### `pnpm-audit-hook: not built`

**Cause:** Distribution files missing
**Fix:**
```bash
pnpm run build
# Or reinstall
pnpm remove pnpm-audit-hook
pnpm add -D pnpm-audit-hook
```

---

## Configuration Troubleshooting

### Debug Configuration Loading

```bash
# Enable debug logging
PNPM_AUDIT_DEBUG=true pnpm install

# Or use CLI flag
pnpm-audit-scan --debug
```

Debug output example:
```
[debug] Loading config from .pnpm-audit.yaml
[debug] Config loaded: {
  policy: { block: ['critical', 'high'], warn: ['medium', 'low', 'unknown'] },
  sources: { github: { enabled: true }, osv: { enabled: true }, nvd: { enabled: true } },
  ...
}
[debug] Environment variables override: PNPM_AUDIT_BLOCK_SEVERITY=medium
[debug] Final config: { policy: { block: ['critical', 'high', 'medium'] }, ... }
```

### Configuration Validation

```bash
# Validate configuration file
node -e "
const YAML = require('yaml');
const fs = require('fs');
try {
  const config = YAML.parse(fs.readFileSync('.pnpm-audit.yaml', 'utf8'));
  console.log('✅ Configuration is valid');
  console.log(JSON.stringify(config, null, 2));
} catch (e) {
  console.error('❌ Configuration error:', e.message);
  process.exit(1);
}
"
```

### Environment Variables Override

Check which environment variables are overriding your configuration:

```bash
# List all pnpm-audit environment variables
env | grep -i pnpm_audit

# Common overrides:
# PNPM_AUDIT_BLOCK_SEVERITY=medium
# PNPM_AUDIT_OFFLINE=true
# PNPM_AUDIT_DISABLE_GITHUB=true
# PNPM_AUDIT_DISABLE_OSV=true
```

---

## Diagnostic Tools

### Health Check Commands

#### System Status Check

```bash
# Check installation status
pnpm list -g pnpm-audit-hook

# Check database status
pnpm-audit-scan --db-status

# Check version
pnpm-audit-scan --version
```

#### Network Connectivity Test

```bash
# Test GitHub API
curl -I https://api.github.com/rate_limit

# Test OSV API
curl -I https://api.osv.dev/v1/query

# Test registry
curl -I https://registry.npmjs.org/
```

#### Configuration Validation

```bash
# Validate config syntax
node -e "require('yaml').parse(require('fs').readFileSync('.pnpm-audit.yaml', 'utf8'))"

# Test configuration loading
pnpm-audit-scan --debug --format json | jq '.config'
```

### Environment Checks

#### Node.js Environment

```bash
# Check Node.js version (requires >=18)
node --version

# Check npm/pnpm versions
npm --version
pnpm --version
```

#### Permission Checks

```bash
# Check pnpm global bin permissions
ls -la $(pnpm bin -g)

# Check project permissions
ls -la .pnpm-audit*
```

### Log Analysis

#### Enable Verbose Logging

```bash
# Verbose mode
PNPM_AUDIT_VERBOSE=true pnpm install

# Debug mode (most detailed)
PNPM_AUDIT_DEBUG=true pnpm install
```

#### Analyze Audit Results

```bash
# Get detailed JSON output
pnpm-audit-scan --format json > audit-results.json

# Analyze with jq
cat audit-results.json | jq '.findings[] | {package, version, severity}'

# Count findings by severity
cat audit-results.json | jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'
```

---

## FAQ

### General Questions

#### Q: What's the difference between `pnpm audit` and `pnpm-audit-hook`?

**A:** `pnpm audit` runs after dependencies are installed, while `pnpm-audit-hook` runs before downloads, preventing vulnerable code from reaching `node_modules`. Think of it as a firewall vs. a scanner.

#### Q: Does this work with npm or yarn?

**A:** No, this is specifically designed for pnpm. Use `npm audit` or `yarn audit` for other package managers.

#### Q: Will this slow down my installs?

**A:** Minimal impact for cached/first-time installs. Subsequent installs use cached results. Use `PNPM_AUDIT_OFFLINE=true` for fastest audits.

#### Q: Can I use this in CI/CD?

**A:** Yes! We provide special output formats for GitHub Actions, Azure DevOps, and AWS CodeBuild. See [CI/CD Integration](../README.md#cicd-integration).

### Configuration Questions

#### Q: How do I allowlist a false positive?

**A:** Add to `.pnpm-audit.yaml`:
```yaml
policy:
  allowlist:
    - id: CVE-2024-12345
      reason: "False positive - not exploitable in our context"
```

#### Q: How do I only block critical vulnerabilities?

**A:** Set severity threshold:
```yaml
policy:
  block:
    - critical
  warn:
    - high
    - medium
    - low
```

Or use environment variable:
```bash
PNPM_AUDIT_BLOCK_SEVERITY=critical pnpm install
```

#### Q: Can I disable specific sources?

**A:** Yes:
```yaml
sources:
  github:
    enabled: false
  osv:
    enabled: true
  nvd:
    enabled: true
```

Or via environment:
```bash
PNPM_AUDIT_DISABLE_GITHUB=true pnpm install
```

### Performance Questions

#### Q: How can I speed up audits?

**A:** 
1. Set `GITHUB_TOKEN` for higher rate limits
2. Use offline mode: `PNPM_AUDIT_OFFLINE=true`
3. Cache `.pnpm-audit-cache/` between CI runs
4. Use static database (bundled with package)

#### Q: Why are audits slow in CI?

**A:** Common causes:
- No `GITHUB_TOKEN` set (rate limits)
- Network latency to APIs
- Large number of dependencies

**Solutions:**
```bash
# Set token
export GITHUB_TOKEN=your_token

# Use offline mode for speed
PNPM_AUDIT_OFFLINE=true pnpm install
```

### Security Questions

#### Q: Is this secure? Can it be bypassed?

**A:** Yes, like any security tool, it can be bypassed with `--ignore-pnpmfile`. This is intentional for development flexibility. In CI, you can enforce it via policy.

#### Q: How often is the vulnerability database updated?

**A:** The static database is updated with each package release. Live sources (GitHub, OSV, NVD) check in real-time.

#### Q: Does this check transitive dependencies?

**A:** Yes! It checks all resolved packages, including transitive dependencies, and shows dependency chains in output.

### Integration Questions

#### Q: How do I integrate with GitHub Actions?

**A:** Add to your workflow:
```yaml
- name: Security Audit
  run: |
    pnpm install
    pnpm-audit-scan --format github
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Q: Can I use this with monorepos?

**A:** Yes! Run in each workspace or at root level. The tool scans the current `pnpm-lock.yaml`.

#### Q: How do I exclude certain packages from auditing?

**A:** Use the allowlist in configuration:
```yaml
policy:
  allowlist:
    - package: lodash
      reason: "Development dependency, not in production bundle"
```

---

## Community Resources

### Getting Help

#### GitHub Issues
- **Bug reports:** [github.com/asx8678/pnpm-audit-hook/issues](https://github.com/asx8678/pnpm-audit-hook/issues)
- **Feature requests:** Use "enhancement" label
- **Questions:** Use "question" label

#### Contributing
- Check open issues for "good first issue" label
- See [README](../README.md#local-development) for development setup

#### Support Channels
- **GitHub Discussions:** For general questions
- **Stack Overflow:** Tag with `pnpm-audit-hook`
- **Twitter:** @pnpm_audit_hook (fictional for example)

### Useful Links

- [README](../README.md) - Main documentation
- [Configuration Reference](../README.md#configuration) - All config options
- [CLI Reference](../README.md#cli-reference) - Command line options
- [CI/CD Integration](../README.md#cicd-integration) - Setup guides
- [Security Model](../README.md#security-model) - How it works

### Reporting Issues

When reporting issues, please include:

1. **Version info:**
   ```bash
   pnpm-audit-scan --version
   node --version
   pnpm --version
   ```

2. **Configuration:**
   ```bash
   cat .pnpm-audit.yaml
   ```

3. **Debug output:**
   ```bash
   PNPM_AUDIT_DEBUG=true pnpm-audit-scan 2>&1 | tee debug.log
   ```

4. **Environment:**
   ```bash
   env | grep -i pnpm_audit
   ```

---

## Still Need Help?

If you're still experiencing issues:

1. **Search existing issues:** [GitHub Issues](https://github.com/asx8678/pnpm-audit-hook/issues)
2. **Check documentation:** [README](../README.md)
3. **Create new issue:** Include all diagnostic information above

Remember: The more information you provide, the faster we can help!