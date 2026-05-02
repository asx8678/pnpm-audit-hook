/**
 * Tests for security utilities.
 *
 * Covers: path traversal prevention, lockfile validation, SSRF protection,
 * XSS prevention, malicious content detection, and input validation.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  isSafeRelativePath,
  safePathResolve,
  SecurityError,
  validateLockfileStructure,
  isSafeUrl,
  escapeHtml,
  sanitizeTerminalOutput,
  sanitizeLogMessage,
  detectMaliciousContent,
  isSecurePackageName,
  validateConfigString,
  validateConfigUrl,
} from "../../src/utils/security.js";

// ─────────────────────────────────────────────────────
// §1  Path Traversal Prevention
// ─────────────────────────────────────────────────────

describe("isSafeRelativePath", () => {
  it("allows simple relative paths", () => {
    assert.equal(isSafeRelativePath("data/file.json"), true);
    assert.equal(isSafeRelativePath("src/utils/security.ts"), true);
    assert.equal(isSafeRelativePath("package.json"), true);
    assert.equal(isSafeRelativePath("a/b/c/d.json"), true);
  });

  it("rejects absolute paths", () => {
    assert.equal(isSafeRelativePath("/etc/passwd"), false);
    assert.equal(isSafeRelativePath("/home/user/.ssh/id_rsa"), false);
  });

  it("rejects path traversal", () => {
    assert.equal(isSafeRelativePath("../../../etc/passwd"), false);
    assert.equal(isSafeRelativePath("data/../../etc/passwd"), false);
    assert.equal(isSafeRelativePath("./../secret"), false);
    assert.equal(isSafeRelativePath(".."), false);
  });

  it("rejects null byte injection", () => {
    assert.equal(isSafeRelativePath("data/file.json\x00.jpg"), false);
    assert.equal(isSafeRelativePath("\x00/etc/passwd"), false);
  });

  it("rejects control characters", () => {
    assert.equal(isSafeRelativePath("data/file\x01.json"), false);
    assert.equal(isSafeRelativePath("data/file\n.json"), false);
    assert.equal(isSafeRelativePath("data/file\r.json"), false);
  });

  it("rejects empty strings", () => {
    assert.equal(isSafeRelativePath(""), false);
  });

  it("rejects strings exceeding max length", () => {
    assert.equal(isSafeRelativePath("a".repeat(5000)), false);
  });

  it("normalizes backslash traversal", () => {
    assert.equal(isSafeRelativePath("data\\..\\..\\etc\\passwd"), false);
  });
});

describe("safePathResolve", () => {
  it("resolves safe paths within base directory", () => {
    const result = safePathResolve("/project", "data/file.json");
    assert.equal(result, "/project/data/file.json");
  });

  it("throws for traversal attempts", () => {
    assert.throws(
      () => safePathResolve("/project", "../../../etc/passwd"),
      SecurityError,
    );
  });

  it("throws for absolute path injection", () => {
    assert.throws(
      () => safePathResolve("/project", "/etc/passwd"),
      SecurityError,
    );
  });
});

// ─────────────────────────────────────────────────────
// §2  Lockfile Structure Integrity Validation
// ─────────────────────────────────────────────────────

describe("validateLockfileStructure", () => {
  it("validates a normal lockfile", () => {
    const lockfile = {
      lockfileVersion: "9.0",
      packages: {
        "react@18.2.0": { resolution: { integrity: "abc123" } },
        "lodash@4.17.21": { resolution: { integrity: "def456" } },
      },
      importers: {
        ".": {
          dependencies: { react: "18.2.0" },
        },
      },
    };
    const result = validateLockfileStructure(lockfile);
    assert.equal(result.valid, true);
    assert.equal(result.packageCount, 2);
    assert.equal(result.warnings.length, 0);
  });

  it("rejects non-object lockfiles", () => {
    assert.equal(validateLockfileStructure(null).valid, false);
    assert.equal(validateLockfileStructure(undefined).valid, false);
    assert.equal(validateLockfileStructure("string").valid, false);
    assert.equal(validateLockfileStructure([1, 2, 3]).valid, false);
  });

  it("warns on prototype pollution in package keys", () => {
    // Real attack vector: a crafted lockfile key containing __proto__ path segment
    const lockfile = {
      packages: {
        "node_modules/__proto__/evil@1.0.0": { resolution: {} },
        "react@18.2.0": { resolution: {} },
      },
    };
    const result = validateLockfileStructure(lockfile);
    assert.ok(result.warnings.some(w => w.includes("Prototype pollution")));
  });

  it("warns on constructor/prototype keys at top level", () => {
    // Realistic: a malicious lockfile with "constructor" or "prototype" as top-level keys
    const malicious = Object.create(null);
    malicious.constructor = { polluted: true };
    malicious.packages = {};
    // Object.keys WILL enumerate constructor on Object.create(null) objects
    const result = validateLockfileStructure(malicious);
    assert.ok(result.warnings.some(w => w.includes("constructor")));
  });

  it("warns on control characters in keys", () => {
    const lockfile = {
      packages: {
        "react@18.2.0": {},
        "evil\x00pkg@1.0.0": {},
      },
    };
    const result = validateLockfileStructure(lockfile);
    assert.ok(result.warnings.some(w => w.includes("control characters")));
  });

  it("warns on unusual lockfileVersion", () => {
    const lockfile = {
      lockfileVersion: -1,
      packages: {},
    };
    const result = validateLockfileStructure(lockfile);
    assert.ok(result.warnings.some(w => w.includes("lockfileVersion")));
  });
});

// ─────────────────────────────────────────────────────
// §3  SSRF Protection
// ─────────────────────────────────────────────────────

describe("isSafeUrl", () => {
  it("allows safe public URLs", () => {
    assert.equal(isSafeUrl("https://registry.npmjs.org/react").safe, true);
    assert.equal(isSafeUrl("https://api.github.com/repos/test").safe, true);
    assert.equal(isSafeUrl("http://example.com/data.json").safe, true);
  });

  it("rejects non-HTTP protocols", () => {
    assert.equal(isSafeUrl("file:///etc/passwd").safe, false);
    assert.equal(isSafeUrl("ftp://example.com/file").safe, false);
    assert.equal(isSafeUrl("gopher://example.com").safe, false);
    assert.equal(isSafeUrl("javascript:alert(1)").safe, false);
  });

  it("rejects localhost", () => {
    assert.equal(isSafeUrl("http://localhost/secret").safe, false);
    assert.equal(isSafeUrl("http://localhost:8080/admin").safe, false);
    assert.equal(isSafeUrl("http://[::1]/secret").safe, false);
  });

  it("rejects private IP ranges", () => {
    assert.equal(isSafeUrl("http://192.168.1.1/secret").safe, false);
    assert.equal(isSafeUrl("http://10.0.0.1/metadata").safe, false);
    assert.equal(isSafeUrl("http://172.16.0.1/data").safe, false);
    assert.equal(isSafeUrl("http://127.0.0.1/secret").safe, false);
    assert.equal(isSafeUrl("http://169.254.169.254/latest/meta-data").safe, false);
  });

  it("rejects cloud metadata endpoints", () => {
    assert.equal(isSafeUrl("http://169.254.169.254/latest/meta-data/").safe, false);
    assert.equal(isSafeUrl("http://metadata.google.internal/computeMetadata/v1/").safe, false);
  });

  it("rejects internal hostnames", () => {
    assert.equal(isSafeUrl("http://myserver.internal/data").safe, false);
    assert.equal(isSafeUrl("http://host.local/secret").safe, false);
  });

  it("rejects invalid URLs", () => {
    assert.equal(isSafeUrl("not-a-url").safe, false);
    assert.equal(isSafeUrl("").safe, false);
  });

  it("rejects IPv6 loopback", () => {
    assert.equal(isSafeUrl("http://[::1]/secret").safe, false);
  });
});

// ─────────────────────────────────────────────────────
// §4  XSS Prevention
// ─────────────────────────────────────────────────────

describe("escapeHtml", () => {
  it("escapes HTML special characters", () => {
    assert.equal(
      escapeHtml("<script>alert('xss')</script>"),
      "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
    );
    assert.equal(escapeHtml("a & b"), "a &amp; b");
    assert.equal(escapeHtml('"quoted"'), "&quot;quoted&quot;");
  });

  it("leaves safe strings unchanged", () => {
    assert.equal(escapeHtml("hello world"), "hello world");
    assert.equal(escapeHtml("123"), "123");
  });
});

describe("sanitizeTerminalOutput", () => {
  it("strips ANSI escape codes", () => {
    assert.equal(sanitizeTerminalOutput("\x1b[31mred text\x1b[0m"), "red text");
    assert.equal(sanitizeTerminalOutput("\x1b[1;32mbold green\x1b[0m"), "bold green");
  });

  it("strips control characters", () => {
    assert.equal(sanitizeTerminalOutput("hello\x00world"), "helloworld");
    assert.equal(sanitizeTerminalOutput("test\x07beep"), "testbeep");
  });
});

describe("sanitizeLogMessage", () => {
  it("strips newlines and control characters", () => {
    assert.equal(sanitizeLogMessage("line1\nline2"), "line1line2");
    assert.equal(sanitizeLogMessage("line1\r\nline2"), "line1line2");
    assert.equal(sanitizeLogMessage("test\x00injection"), "testinjection");
  });
});

// ─────────────────────────────────────────────────────
// §5  Malicious Content Detection
// ─────────────────────────────────────────────────────

describe("detectMaliciousContent", () => {
  it("detects prototype pollution patterns", () => {
    const threats = detectMaliciousContent("value__proto__polluted", "config-value");
    assert.ok(threats.some(t => t.includes("Prototype pollution")));
  });

  it("detects null byte injection", () => {
    const threats = detectMaliciousContent("data\x00evil", "config-value");
    assert.ok(threats.some(t => t.includes("Null byte")));
  });

  it("detects excessively long strings", () => {
    const threats = detectMaliciousContent("x".repeat(20_000), "config-value");
    assert.ok(threats.some(t => t.includes("safe length")));
  });

  it("allows clean strings", () => {
    assert.equal(detectMaliciousContent("normal-value", "config-value").length, 0);
    assert.equal(detectMaliciousContent("1.2.3", "package-name").length, 0);
  });

  it("detects script injection in config values", () => {
    const threats = detectMaliciousContent("<script>alert(1)</script>", "config-value");
    assert.ok(threats.length > 0);
  });
});

// ─────────────────────────────────────────────────────
// §6  Secure Package Name Validation
// ─────────────────────────────────────────────────────

describe("isSecurePackageName", () => {
  it("allows valid npm package names", () => {
    assert.equal(isSecurePackageName("react"), true);
    assert.equal(isSecurePackageName("@angular/core"), true);
    assert.equal(isSecurePackageName("my-cool-package"), true);
    assert.equal(isSecurePackageName("package.with.dots"), true);
    assert.equal(isSecurePackageName("under_score"), true);
  });

  it("rejects traversal in package names", () => {
    assert.equal(isSecurePackageName("../../../etc/passwd"), false);
    assert.equal(isSecurePackageName("pkg/../../secret"), false);
    assert.equal(isSecurePackageName("@scope/../../../etc"), false);
  });

  it("rejects shell metacharacters", () => {
    assert.equal(isSecurePackageName("pkg; rm -rf /"), false);
    assert.equal(isSecurePackageName("pkg$(whoami)"), false);
    assert.equal(isSecurePackageName("pkg`id`"), false);
    assert.equal(isSecurePackageName("pkg|cat /etc/passwd"), false);
  });

  it("rejects empty or oversized names", () => {
    assert.equal(isSecurePackageName(""), false);
    assert.equal(isSecurePackageName("a".repeat(215)), false);
  });

  it("rejects control characters", () => {
    assert.equal(isSecurePackageName("pkg\x00name"), false);
  });

  it("validates scoped package format", () => {
    assert.equal(isSecurePackageName("@"), false);
    assert.equal(isSecurePackageName("@/pkg"), false);
    assert.equal(isSecurePackageName("@scope/"), false);
    assert.equal(isSecurePackageName("@scope/pkg"), true);
  });
});

// ─────────────────────────────────────────────────────
// §7  Config Input Validation
// ─────────────────────────────────────────────────────

describe("validateConfigString", () => {
  it("returns trimmed non-empty strings", () => {
    assert.equal(validateConfigString("  hello  ", "field"), "hello");
    assert.equal(validateConfigString("value", "field"), "value");
  });

  it("rejects non-strings", () => {
    assert.equal(validateConfigString(123, "field"), null);
    assert.equal(validateConfigString(true, "field"), null);
    assert.equal(validateConfigString(null, "field"), null);
  });

  it("respects maxLength", () => {
    assert.equal(
      validateConfigString("long".repeat(300), "field", { maxLength: 100 })!.length,
      100,
    );
  });

  it("validates against pattern", () => {
    const pattern = /^[a-z]+$/;
    assert.equal(validateConfigString("abc", "field", { pattern }), "abc");
    assert.equal(validateConfigString("abc123", "field", { pattern }), null);
  });

  it("rejects malicious content", () => {
    assert.equal(validateConfigString("__proto__", "field"), null);
    assert.equal(validateConfigString("<script>alert(1)</script>", "field"), null);
  });

  it("allows empty strings when specified", () => {
    assert.equal(validateConfigString("", "field", { allowEmpty: true }), "");
    assert.equal(validateConfigString("  ", "field", { allowEmpty: true }), "");
  });
});

describe("validateConfigUrl", () => {
  it("allows safe URLs", () => {
    assert.equal(
      validateConfigUrl("https://api.example.com", "field"),
      "https://api.example.com",
    );
  });

  it("rejects SSRF URLs", () => {
    assert.equal(validateConfigUrl("http://localhost/admin", "field"), null);
    assert.equal(validateConfigUrl("http://192.168.1.1/secret", "field"), null);
    assert.equal(validateConfigUrl("http://169.254.169.254/", "field"), null);
  });

  it("rejects non-URL strings", () => {
    assert.equal(validateConfigUrl("not-a-url", "field"), null);
    assert.equal(validateConfigUrl("file:///etc/passwd", "field"), null);
  });
});
