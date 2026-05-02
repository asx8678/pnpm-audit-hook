# Phase 6, Task 6.1: Input Validation Security Enhancements

## Summary
Implemented comprehensive input validation security enhancements covering path traversal
prevention, lockfile integrity validation, SSRF protection, XSS prevention, and
malicious content detection. All existing tests continue to pass (198+ tests).

## New File: `src/utils/security.ts`

Centralized security module with 7 sections:

### §1 — Path Traversal Prevention
- **`isSafeRelativePath(p)`** — Validates a path is safe (no absolute injection, `..` traversal, null bytes, control chars)
- **`safePathResolve(base, relative)`** — Resolves a path and throws `SecurityError` if it escapes the base directory

### §2 — Lockfile Structure Integrity Validation
- **`validateLockfileStructure(lockfile)`** — Validates incoming lockfile data:
  - Rejects non-object inputs
  - Detects prototype pollution indicators (`__proto__` in package keys, `constructor`/`prototype` top-level keys)
  - Warns on control characters in keys
  - Checks for reasonable package counts (flags >500k as potential DoS)
  - Validates nesting depth (max 10 levels)
  - Validates `lockfileVersion` is in a sane range

### §3 — SSRF Protection
- **`isSafeUrl(url)`** — Validates a URL is safe to fetch:
  - Only allows `http:` and `https:` protocols
  - Blocks private IPv4 ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
  - Blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal)
  - Blocks `localhost`, `*.internal`, `*.local` hostnames
  - Blocks IPv6 loopback and link-local addresses

### §4 — XSS Prevention / Output Sanitization
- **`escapeHtml(str)`** — Escapes `& < > " '` for safe HTML output
- **`sanitizeTerminalOutput(str)`** — Strips ANSI escape codes and control characters
- **`sanitizeLogMessage(str)`** — Strips newlines and control chars (prevents log injection)

### §5 — Malicious Content Detection
- **`detectMaliciousContent(content, context)`** — Detects:
  - Prototype pollution patterns (`__proto__`, `constructor.prototype`)
  - Command injection patterns (shell metacharacters, template literals)
  - Null byte injection
  - Excessively long strings (>10k chars, DoS protection)
- **`isSecurePackageName(name)`** — Validates npm package names against:
  - Path traversal (`../`, `..\\`)
  - Shell metacharacters (`;`, `|`, `$`, backtick, etc.)
  - Control characters and null bytes
  - Scoped package format (`@scope/name`)
  - Max length (214 chars per npm spec)

### §6 — SecurityError Class
- Custom error class distinguishing security violations from operational errors

### §7 — Config Input Validators
- **`validateConfigString(value, field, options)`** — Validates strings with length limits, regex patterns, and malicious content detection
- **`validateConfigUrl(value, field)`** — Validates URLs combining SSRF protection with string validation

## Integration Points

### `src/config.ts`
- Switched `isValidRelativePath()` to delegate to `isSafeRelativePath()` from security module
- Added malicious content detection on `PNPM_AUDIT_CONFIG_PATH` env var

### `src/static-db/reader.ts`
- Replaced local `isValidPackageName()` + `isValidNameSegment()` with centralized `isSecurePackageName()` from security module
- Eliminates duplicate validation logic (DRY)

### `src/utils/http.ts`
- Added SSRF protection to `HttpClient.requestRaw()` — blocks requests to private/internal networks before any fetch occurs

### `src/audit.ts`
- Added lockfile structure validation at audit entry point
- Logs warnings for any integrity issues found in incoming lockfile data

## Test Coverage: `test/utils/security.test.ts`
50 tests covering all security functions:
- 8 path traversal tests (absolute, traversal, null bytes, control chars, backslashes)
- 6 lockfile validation tests (normal, non-objects, pollution, control chars)
- 8 SSRF protection tests (protocols, localhost, private IPs, cloud metadata)
- 6 XSS prevention tests (HTML escaping, ANSI stripping, log sanitization)
- 5 malicious content detection tests (pollution, null bytes, DoS, injection)
- 6 package name validation tests (valid, traversal, shell chars, scoped)
- 6 config string validation tests (types, length, patterns, malicious content)
- 3 config URL validation tests (safe URLs, SSRF, non-URLs)

## Design Principles Applied
- **DRY**: Centralized all security validation in one module; removed duplicated logic
- **Fail-closed**: Invalid/missing input defaults to rejection
- **Defense-in-depth**: Multiple layers of validation (path, content, SSRF)
- **Separation of concerns**: Security module is independent of business logic
- **Backward compatibility**: All existing tests pass unchanged
