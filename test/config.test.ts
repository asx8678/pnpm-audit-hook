import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { loadConfig, DEFAULT_CONFIG } from "../src/config";

describe("loadConfig", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("returns defaults when config file is missing", async () => {
    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.deepEqual(cfg.policy.block, DEFAULT_CONFIG.policy.block);
    assert.deepEqual(cfg.policy.warn, DEFAULT_CONFIG.policy.warn);
    assert.deepEqual(cfg.policy.allowlist, []);
    assert.equal(cfg.sources.github.enabled, true);
    assert.equal(cfg.sources.nvd.enabled, true);
    assert.equal(cfg.cache.ttlSeconds, 3600);
  });

  it("loads valid YAML config and merges with defaults", async () => {
    const configContent = `
policy:
  block:
    - critical
  warn:
    - high
    - medium
sources:
  github: true
  nvd: false
cache:
  ttlSeconds: 7200
`;
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.deepEqual(cfg.policy.block, ["critical"]);
    assert.deepEqual(cfg.policy.warn, ["high", "medium"]);
    assert.equal(cfg.sources.github.enabled, true);
    assert.equal(cfg.sources.nvd.enabled, false);
    assert.equal(cfg.cache.ttlSeconds, 7200);
  });

  it("throws on invalid YAML syntax", async () => {
    const invalidYaml = `
policy:
  block: [
    - this is invalid yaml
`;
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), invalidYaml);

    await assert.rejects(
      loadConfig({ cwd: tempDir, env: {} }),
      /Failed to read config/
    );
  });

  it("uses env var PNPM_AUDIT_CONFIG_PATH to override config location", async () => {
    const customConfigDir = path.join(tempDir, "custom");
    await fs.mkdir(customConfigDir, { recursive: true });

    const configContent = `
policy:
  block:
    - low
`;
    const customConfigPath = path.join(customConfigDir, "my-config.yaml");
    await fs.writeFile(customConfigPath, configContent);

    const cfg = await loadConfig({
      cwd: tempDir,
      env: { PNPM_AUDIT_CONFIG_PATH: path.join("custom", "my-config.yaml") },
    });

    assert.deepEqual(cfg.policy.block, ["low"]);
  });

  it("handles empty config file (uses defaults)", async () => {
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), "");

    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.deepEqual(cfg.policy.block, DEFAULT_CONFIG.policy.block);
    assert.deepEqual(cfg.policy.warn, DEFAULT_CONFIG.policy.warn);
  });

  it("handles config with only partial policy section", async () => {
    const configContent = `
policy:
  block:
    - critical
`;
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.deepEqual(cfg.policy.block, ["critical"]);
    assert.deepEqual(cfg.policy.warn, DEFAULT_CONFIG.policy.warn);
  });

  it("parses allowlist entries correctly", async () => {
    const configContent = `
policy:
  block:
    - critical
  allowlist:
    - id: CVE-2025-0001
      reason: "Known issue, mitigated"
      expires: "2025-12-31"
    - package: lodash
      reason: "Internal use only"
`;
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.equal(cfg.policy.allowlist.length, 2);
    assert.equal(cfg.policy.allowlist[0]!.id, "CVE-2025-0001");
    assert.equal(cfg.policy.allowlist[0]!.reason, "Known issue, mitigated");
    assert.equal(cfg.policy.allowlist[1]!.package, "lodash");
  });

  it("normalizes severity values to lowercase", async () => {
    const configContent = `
policy:
  block:
    - CRITICAL
    - High
  warn:
    - MEDIUM
    - Low
`;
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.deepEqual(cfg.policy.block, ["critical", "high"]);
    assert.deepEqual(cfg.policy.warn, ["medium", "low"]);
  });

  it("handles sources set to false to disable them", async () => {
    const configContent = `
sources:
  github: false
  nvd: false
`;
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.equal(cfg.sources.github.enabled, false);
    assert.equal(cfg.sources.nvd.enabled, false);
  });

  it("filters out invalid allowlist entries", async () => {
    const configContent = `
policy:
  allowlist:
    - id: CVE-2025-0001
      reason: "Valid entry"
    - "invalid string entry"
    - null
    - 123
`;
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

    const cfg = await loadConfig({ cwd: tempDir, env: {} });

    assert.equal(cfg.policy.allowlist.length, 1);
    assert.equal(cfg.policy.allowlist[0]!.id, "CVE-2025-0001");
  });
});
