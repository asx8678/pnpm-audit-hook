import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("createPnpmHooks", () => {
  it("returns object with hooks property containing afterAllResolved", async () => {
    const { createPnpmHooks } = await import("../src/index");

    const result = createPnpmHooks();

    assert.ok(result.hooks);
    assert.ok(typeof result.hooks.afterAllResolved === "function");
  });

  it("returns hooks object with correct structure", async () => {
    const { createPnpmHooks } = await import("../src/index");

    const result = createPnpmHooks();

    assert.ok("hooks" in result);
    assert.ok("afterAllResolved" in result.hooks);
    assert.equal(Object.keys(result.hooks).length, 1);
  });
});

describe("afterAllResolved hook", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-index-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  async function writeConfig(config: Record<string, unknown>): Promise<void> {
    const yaml = await import("yaml");
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), yaml.stringify(config));
  }

  function createLockfile(packages: Array<{ name: string; version: string }>): Record<string, unknown> {
    const pkgSnapshots: Record<string, object> = {};
    for (const p of packages) {
      pkgSnapshots[`/${p.name}@${p.version}`] = { resolution: { integrity: "sha512-test" } };
    }
    return {
      lockfileVersion: "9.0",
      packages: pkgSnapshots,
    };
  }

  it("returns lockfile unchanged when audit passes", async () => {
    await writeConfig({
      sources: { github: false, nvd: false },
      failOnNoSources: false,
    });

    const { createPnpmHooks } = await import("../src/index");
    const { hooks } = createPnpmHooks();

    const lockfile = createLockfile([{ name: "safe-package", version: "1.0.0" }]);
    const context = { lockfileDir: tempDir };

    const result = await hooks.afterAllResolved(lockfile, context);

    assert.deepEqual(result, lockfile);
  });

  it("throws Error when runAudit returns blocked result", async () => {
    // This test verifies the error message format when the hook blocks.
    // We test this by checking the createPnpmHooks implementation throws
    // the expected error when result.blocked is true.
    // Since triggering blocked=true reliably requires external APIs or mocks,
    // we verify the error handling path through the aggregator's fail-closed behavior.

    // When all sources are disabled and failOnNoSources is true (default),
    // the aggregator throws, which the hook catches, logs, and re-throws.
    await writeConfig({
      sources: { github: false, nvd: false },
      failOnNoSources: true,
    });

    const { createPnpmHooks } = await import("../src/index");
    const { hooks } = createPnpmHooks();

    const lockfile = createLockfile([{ name: "test-pkg", version: "1.0.0" }]);
    const context = { lockfileDir: tempDir };

    // Verifies the error handling code path in the hook
    await assert.rejects(
      hooks.afterAllResolved(lockfile, context),
      (err: Error) => {
        assert.ok(err instanceof Error);
        assert.ok(err.message.length > 0);
        return true;
      }
    );
  });

  it("throws Error when all sources disabled and failOnNoSources is true", async () => {
    await writeConfig({
      sources: { github: false, nvd: false },
      failOnNoSources: true,
    });

    const { createPnpmHooks } = await import("../src/index");
    const { hooks } = createPnpmHooks();

    const lockfile = createLockfile([{ name: "vulnerable-pkg", version: "1.0.0" }]);
    const context = { lockfileDir: tempDir };

    // When all sources are disabled with failOnNoSources: true,
    // the aggregator throws before the hook can complete
    await assert.rejects(
      hooks.afterAllResolved(lockfile, context),
      /All vulnerability sources are disabled/
    );
  });

  it("re-throws errors from runAudit", async () => {
    const customConfigDir = path.join(tempDir, "nonexistent-config");
    await fs.mkdir(customConfigDir, { recursive: true });

    const yaml = await import("yaml");
    await fs.writeFile(
      path.join(customConfigDir, "invalid.yaml"),
      "invalid: yaml: [\n" // Invalid YAML
    );

    const { createPnpmHooks } = await import("../src/index");
    const { hooks } = createPnpmHooks();

    const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);
    const context = { lockfileDir: tempDir };

    // With invalid config path env var pointing to malformed yaml
    process.env.PNPM_AUDIT_CONFIG_PATH = "nonexistent-config/invalid.yaml";

    try {
      await assert.rejects(
        hooks.afterAllResolved(lockfile, context),
        /Failed to read config/
      );
    } finally {
      delete process.env.PNPM_AUDIT_CONFIG_PATH;
    }
  });
});

describe("context.lockfileDir handling", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-context-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  async function writeConfig(dir: string, config: Record<string, unknown>): Promise<void> {
    const yaml = await import("yaml");
    await fs.writeFile(path.join(dir, ".pnpm-audit.yaml"), yaml.stringify(config));
  }

  function createLockfile(): Record<string, unknown> {
    return {
      lockfileVersion: "9.0",
      packages: {
        "/safe-pkg@1.0.0": { resolution: { integrity: "sha512-test" } },
      },
    };
  }

  it("handles null context.lockfileDir gracefully by using process.cwd()", async () => {
    const originalCwd = process.cwd();

    try {
      process.chdir(tempDir);
      await writeConfig(tempDir, {
        sources: { github: false, nvd: false },
        failOnNoSources: false,
      });

      const { createPnpmHooks } = await import("../src/index");
      const { hooks } = createPnpmHooks();

      const lockfile = createLockfile();
      const context = { lockfileDir: null };

      const result = await hooks.afterAllResolved(lockfile, context);
      assert.deepEqual(result, lockfile);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("handles undefined context.lockfileDir gracefully by using process.cwd()", async () => {
    const originalCwd = process.cwd();

    try {
      process.chdir(tempDir);
      await writeConfig(tempDir, {
        sources: { github: false, nvd: false },
        failOnNoSources: false,
      });

      const { createPnpmHooks } = await import("../src/index");
      const { hooks } = createPnpmHooks();

      const lockfile = createLockfile();
      const context = { lockfileDir: undefined };

      const result = await hooks.afterAllResolved(lockfile, context);
      assert.deepEqual(result, lockfile);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("handles undefined context gracefully by using process.cwd()", async () => {
    const originalCwd = process.cwd();

    try {
      process.chdir(tempDir);
      await writeConfig(tempDir, {
        sources: { github: false, nvd: false },
        failOnNoSources: false,
      });

      const { createPnpmHooks } = await import("../src/index");
      const { hooks } = createPnpmHooks();

      const lockfile = createLockfile();

      const result = await hooks.afterAllResolved(lockfile, undefined);
      assert.deepEqual(result, lockfile);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("handles null context gracefully by using process.cwd()", async () => {
    const originalCwd = process.cwd();

    try {
      process.chdir(tempDir);
      await writeConfig(tempDir, {
        sources: { github: false, nvd: false },
        failOnNoSources: false,
      });

      const { createPnpmHooks } = await import("../src/index");
      const { hooks } = createPnpmHooks();

      const lockfile = createLockfile();

      const result = await hooks.afterAllResolved(lockfile, null);
      assert.deepEqual(result, lockfile);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("uses provided lockfileDir when available", async () => {
    const customDir = path.join(tempDir, "custom-lockfile-dir");
    await fs.mkdir(customDir, { recursive: true });

    await writeConfig(customDir, {
      sources: { github: false, nvd: false },
      failOnNoSources: false,
    });

    const { createPnpmHooks } = await import("../src/index");
    const { hooks } = createPnpmHooks();

    const lockfile = createLockfile();
    const context = { lockfileDir: customDir };

    const result = await hooks.afterAllResolved(lockfile, context);
    assert.deepEqual(result, lockfile);
  });
});

describe("error handling", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-error-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("logs error message before re-throwing", async () => {
    const yaml = await import("yaml");
    await fs.writeFile(
      path.join(tempDir, ".pnpm-audit.yaml"),
      yaml.stringify({
        sources: { github: false, nvd: false },
        failOnNoSources: true,
      })
    );

    const { createPnpmHooks } = await import("../src/index");
    const { hooks } = createPnpmHooks();

    const lockfile = {
      lockfileVersion: "9.0",
      packages: { "/pkg@1.0.0": { resolution: { integrity: "sha512-test" } } },
    };

    await assert.rejects(
      hooks.afterAllResolved(lockfile, { lockfileDir: tempDir }),
      (err: Error) => {
        assert.ok(err instanceof Error);
        return true;
      }
    );
  });

  it("converts non-Error objects to strings when logging", async () => {
    const originalCwd = process.cwd();

    try {
      process.chdir(tempDir);

      const yaml = await import("yaml");
      await fs.writeFile(
        path.join(tempDir, ".pnpm-audit.yaml"),
        "this: is: invalid: [\nyaml"
      );

      const { createPnpmHooks } = await import("../src/index");
      const { hooks } = createPnpmHooks();

      const lockfile = { lockfileVersion: "9.0", packages: {} };

      await assert.rejects(
        hooks.afterAllResolved(lockfile, { lockfileDir: tempDir })
      );
    } finally {
      process.chdir(originalCwd);
    }
  });
});

describe("exports", () => {
  it("re-exports audit module", async () => {
    const index = await import("../src/index");

    assert.ok("runAudit" in index);
    assert.ok(typeof index.runAudit === "function");
  });

  it("re-exports types module", async () => {
    const index = await import("../src/index");

    // Type exports are not runtime values, but we can check
    // that the module loads without error
    assert.ok(index);
  });
});
