"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createAuditHooks } = require("../src/audit-hook.cjs");

function createHarness(t, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pnpm-audit-hook-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const policyPath = path.join(dir, "policy.json");
  if (typeof options.rawPolicy === "string") {
    fs.writeFileSync(policyPath, options.rawPolicy);
  } else if (options.policy) {
    fs.writeFileSync(policyPath, JSON.stringify(options.policy, null, 2));
  }

  const env = {
    ...options.env,
    PNPM_AUDIT_POLICY_PATH: policyPath,
  };

  return {
    hooks: createAuditHooks({ cwd: dir, env, fs }),
  };
}

test("allows packages when no policy file exists", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pnpm-audit-hook-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const hooks = createAuditHooks({
    cwd: dir,
    env: {
      PNPM_AUDIT_POLICY_PATH: path.join(dir, "missing-policy.json"),
    },
    fs,
  });

  const packageJson = { name: "safe-package", version: "1.0.0" };
  assert.equal(hooks.readPackage(packageJson), packageJson);
});

test("blocks packages that match a deny rule", (t) => {
  const { hooks } = createHarness(t, {
    policy: {
      rules: [
        {
          name: "blocked-package",
          versions: ["2.1.0"],
          reason: "Known vulnerability",
        },
      ],
    },
  });

  assert.throws(
    () => hooks.readPackage({ name: "blocked-package", version: "2.1.0" }),
    /Blocked package blocked-package@2.1.0/
  );
});

test("supports wildcard version matching in rules", (t) => {
  const { hooks } = createHarness(t, {
    policy: {
      rules: [
        {
          name: "blocked-package",
          versions: ["3.4.*"],
        },
      ],
    },
  });

  assert.throws(
    () => hooks.readPackage({ name: "blocked-package", version: "3.4.8" }),
    /Blocked package blocked-package@3.4.8/
  );
  assert.doesNotThrow(() =>
    hooks.readPackage({ name: "blocked-package", version: "3.5.0" })
  );
});

test("warns instead of throwing when onViolation is warn", (t) => {
  const { hooks } = createHarness(t, {
    policy: {
      onViolation: "warn",
      rules: [{ name: "blocked-package" }],
    },
  });
  const logs = [];

  const packageJson = { name: "blocked-package", version: "5.0.0" };
  assert.equal(hooks.readPackage(packageJson, { log: (message) => logs.push(message) }), packageJson);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /Blocked package blocked-package@5.0.0/);
});

test("fails closed on invalid policy by default", (t) => {
  const { hooks } = createHarness(t, {
    rawPolicy: "{invalid-json",
  });

  assert.throws(
    () => hooks.readPackage({ name: "safe-package", version: "1.0.0" }),
    /Invalid JSON/
  );
});

test("fails open on policy read errors when onError=warn", (t) => {
  const { hooks } = createHarness(t, {
    rawPolicy: "{invalid-json",
    env: {
      PNPM_AUDIT_ON_ERROR: "warn",
    },
  });
  const logs = [];

  const packageJson = { name: "safe-package", version: "1.0.0" };
  assert.equal(hooks.readPackage(packageJson, { log: (message) => logs.push(message) }), packageJson);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /Continuing because onError=warn/);
});

test("uses policy-level onError=warn for invalid rules", (t) => {
  const { hooks } = createHarness(t, {
    policy: {
      onError: "warn",
      rules: [{ name: "broken", versions: [] }],
    },
  });
  const logs = [];

  const packageJson = { name: "safe-package", version: "1.0.0" };
  assert.equal(hooks.readPackage(packageJson, { log: (message) => logs.push(message) }), packageJson);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /rules\[0\]\.versions/);
});

test("validates invalid behavior values", (t) => {
  const { hooks } = createHarness(t, {
    policy: {},
    env: {
      PNPM_AUDIT_ON_VIOLATION: "invalid",
    },
  });

  assert.throws(
    () => hooks.readPackage({ name: "safe-package", version: "1.0.0" }),
    /Invalid PNPM_AUDIT_ON_VIOLATION/
  );
});
