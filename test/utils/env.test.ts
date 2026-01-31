import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getRegistryUrl } from "../../src/utils/env";

describe("getRegistryUrl", () => {
  it("returns PNPM_REGISTRY if set", () => {
    const url = getRegistryUrl({ PNPM_REGISTRY: "https://custom.registry.com/" });
    assert.equal(url, "https://custom.registry.com/");
  });

  it("falls back to npm_config_registry", () => {
    const url = getRegistryUrl({ npm_config_registry: "https://npm.example.com" });
    assert.equal(url, "https://npm.example.com/");
  });

  it("adds trailing slash if missing", () => {
    const url = getRegistryUrl({ PNPM_REGISTRY: "https://example.com" });
    assert.equal(url, "https://example.com/");
  });

  it("defaults to npmjs.org", () => {
    const url = getRegistryUrl({});
    assert.equal(url, "https://registry.npmjs.org/");
  });
});
