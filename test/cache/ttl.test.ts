import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ttlForFindings } from "../../src/cache/ttl";
import type { VulnerabilityFinding } from "../../src/types";

function mockFinding(severity: string): VulnerabilityFinding {
  return {
    id: "TEST-001",
    source: "github",
    packageName: "test",
    packageVersion: "1.0.0",
    severity: severity as any,
  };
}

describe("ttlForFindings", () => {
  it("returns 15 minutes for critical severity", () => {
    const ttl = ttlForFindings(3600, [mockFinding("critical")]);
    assert.equal(ttl, 15 * 60);
  });

  it("returns 30 minutes for high severity", () => {
    const ttl = ttlForFindings(3600, [mockFinding("high")]);
    assert.equal(ttl, 30 * 60);
  });

  it("returns 60 minutes for medium severity", () => {
    const ttl = ttlForFindings(3600, [mockFinding("medium")]);
    assert.equal(ttl, 60 * 60);
  });

  it("returns base TTL for low severity", () => {
    const ttl = ttlForFindings(3600, [mockFinding("low")]);
    assert.equal(ttl, 3600);
  });

  it("returns base TTL for empty findings", () => {
    const ttl = ttlForFindings(3600, []);
    assert.equal(ttl, 3600);
  });

  it("uses max severity when multiple findings", () => {
    const ttl = ttlForFindings(3600, [mockFinding("low"), mockFinding("critical"), mockFinding("medium")]);
    assert.equal(ttl, 15 * 60); // critical wins
  });

  it("enforces minimum TTL of 60 seconds", () => {
    const ttl = ttlForFindings(30, [mockFinding("critical")]);
    assert.equal(ttl, 60);
  });
});
