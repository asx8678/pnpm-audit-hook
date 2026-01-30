# pnpm-audit-hook simplification review

Goal: keep only the functionality needed to block compromised/vulnerable installs and warn on non‑serious issues, with reliable downloading and preservation of vulnerability data from a few sources.

Below are 100 concrete simplification opportunities. Each item is intentionally small and actionable.

1. Remove Azure DevOps integration (`src/integrations/azure-devops.ts`, `azure-pipelines/*`) to reduce surface area.
2. Delete PR comment support and VSO logging; keep only local/CI exit code behavior.
3. Drop SARIF/JUnit/SBOM/HTML/Markdown reporters; keep a single JSON report and a concise console summary.
4. Remove the audit trail NDJSON writer (`src/utils/audit-trail.ts`) unless required for compliance.
5. Remove `scripts/warm-cache.ts`, `scripts/generate-baseline.ts`, and `scripts/sync-offline-db.ts` if offline snapshots are out of scope.
6. Remove allowlist logic (`src/policies/allowlist.ts`) to reduce policy complexity.
7. Remove blocklist logic (`src/policies/blocklist.ts`) unless you maintain a small, curated malicious list.
8. Remove grace period handling to keep severity decisions deterministic.
9. Remove `unknownVulnData` policy; use a fixed rule: CI blocks on missing data, local warns.
10. Remove emergency bypass tokens (`PNPM_AUDIT_BYPASS*`) to prevent accidental policy escape.
11. Remove `PNPM_AUDIT_FAIL_ON_WARN`; keep a single rule set for local vs CI.
12. Remove `PNPM_AUDIT_SEVERITY_THRESHOLD` override; put thresholds only in config.
13. Reduce vulnerability sources to the few you actually trust and need (e.g., OSV + npm advisory); disable the rest.
14. Drop NVD enrichment if you only need base severity; it adds latency and failure modes.
15. Drop OSS Index support if not a required source.
16. Drop GitHub Advisories if OSV/npm data is sufficient and you want fewer tokens/limits.
17. Normalize all findings into one canonical schema once, at source boundaries.
18. Deduplicate findings by `(source,id,package,version)` rather than only `package@version:id` to avoid collisions.
19. Make “compromised package” a distinct flag (malicious/yanked/typosquat) that always blocks.
20. Treat integrity mismatch (lockfile vs registry) as a hard block with a clear reason.
21. Replace configurable concurrency with a fixed small value (e.g., 4) to simplify tuning.
22. Remove `performance.earlyExitOnBlock` and just short‑circuit evaluation when a block is confirmed.
23. Collapse cache layers into a single file cache with an in‑memory map for the current run.
24. Remove `ReadOnlyCache` unless offline snapshots are explicitly required.
25. Simplify cache TTL to a single static value.
26. Use atomic writes for cache files (write temp, fsync, rename).
27. Validate JSON before overwriting cache; if invalid, keep last known good.
28. Store per‑source metadata (timestamp, URL, ETag/Last‑Modified) next to cached payloads.
29. Build a combined, canonical “merged” DB file per run to reduce parse/merge work later.
30. Keep a “last good merge” file to recover from bad downloads.
31. Move all decision logic into a single pure function for easy testing.
32. Reduce policy to two thresholds: `blockAboveOrEqual` and `warnAboveOrEqual`.
33. Map unknown severity to `warn` locally and `block` in CI by rule, not config.
34. Remove per‑package decision arrays if you only need a global result.
35. When per‑package detail is desired, store only blocking/warning findings (not allows).
36. Replace `summarizeFindings` with a single counter collected during evaluation.
37. Remove `countFindingsByDecision`; compute counters inline.
38. Remove `summarizePackageDecisions` if unused.
39. Simplify `runAudit` into three steps: parse lockfile → fetch findings → decide.
40. Drop deep config merge logic; just parse a minimal config shape with defaults.
41. Remove Ajv schema validation if config is minimal; validate manually.
42. Prefer JSON config over YAML to remove the YAML dependency.
43. Remove env overrides except `PNPM_AUDIT_CONFIG_PATH` and a `PNPM_AUDIT_MODE=ci|local`.
44. Replace `createRuntimeFromEnv` with a plain options object passed in.
45. Inline `envLogLevel` and custom logger; use `console` with a single prefix.
46. Remove custom HTTP/retry utilities if `fetch` with a timeout is enough.
47. If retries are needed, implement one simple retry with backoff in‑line.
48. Remove custom `utils/markdown.ts` if Markdown output is dropped.
49. Remove `reporters/*` folder if only JSON output remains.
50. Remove SBOM generation logic; it is out of scope for “block compromised installs.”
51. Remove JUnit reporter; it adds XML generation complexity for little value.
52. Remove SARIF reporter; pipeline security views are out of scope if you only need blocking.
53. Remove HTML reporter; JSON + console summary is sufficient.
54. Remove the CLI (`src/cli.ts`) if the hook is the only entrypoint.
55. If CLI is kept, limit it to `--lockfile` and `--mode` only.
56. Remove `utils/semver.ts` if you can rely on source‑provided ranges without extra normalization.
57. If semver handling is needed, keep only a tiny adapter that normalizes pnpm peer suffixes.
58. Remove `utils/severity.ts` if you keep severity strings directly.
59. Remove `utils/cvss.ts` if you are not scoring; use source severity.
60. Remove `utils/concurrency.ts` if you decide on sequential fetches or simple `Promise.all`.
61. Remove `utils/npm-registry.ts` if you drop registry integrity verification.
62. If integrity verification is kept, only implement `fetchVersionManifest` and `extractDistIntegrity` in one file.
63. Combine integrity checks into the main evaluation loop to avoid separate passes.
64. Remove `utils/runtime.ts` if it only wraps env and cwd.
65. Remove `utils/env.ts` if it only parses booleans.
66. Remove `utils/hash.ts` if only used for SHA512 check; use a simple prefix check.
67. Eliminate `LayeredCache` if only one cache store remains.
68. Remove `cache/ttl.ts` if TTL is a simple timestamp check.
69. Reduce `types.ts` to only the fields used by the simplified flow.
70. Stop exporting internal helpers from `src/index.ts`; export only `createPnpmHooks`.
71. Collapse multiple config fields into a single “policy” object with two thresholds and a mode.
72. Add a single “source list” config field to explicitly control allowed sources.
73. When a source download fails, keep last good data and mark the source failed.
74. In CI mode, treat any failed source as a block (fail closed).
75. In local mode, treat failed sources as a warning, not a block.
76. Log one clear summary line: “blocked/warn/clean” plus counts.
77. Make outputs deterministic by sorting packages and findings before writing.
78. Store normalized package keys (`name@version`) once and reuse to avoid repeated string ops.
79. Avoid per‑package HTTP calls if a source supports batch queries (e.g., OSV batch).
80. Cap maximum findings per package in output to keep reports small.
81. Add a tiny unit test suite for the decision function: block, warn, allow.
82. Add a test for integrity mismatch always blocking.
83. Add a test for “missing source in CI blocks.”
84. Add a test for “missing source locally warns.”
85. Add a test for deduping the same finding from two sources.
86. Add a test for corrupted cache file fallback to last good.
87. Add a test for atomic cache write behavior (tmp file rename).
88. Add a test for canonical merge schema integrity.
89. Remove tests that cover deleted features (SBOM, SARIF, Azure, allowlist).
90. Update README to describe only the minimal flow and requirements.
91. Replace the long env var table with just 2–3 required variables.
92. Provide a minimal `.pnpm-audit.yaml` example with only thresholds and sources.
93. Add a small “CI vs local behavior” section with exact blocking rules.
94. Document the cache directory layout and the “last good” fallback behavior.
95. Provide a one‑line troubleshooting tip for source download failures.
96. Remove `dist/` from source control unless you intentionally vendor built output.
97. If you keep `dist/`, add a note that hook uses built JS and the source is for dev.
98. Remove the `azure-pipelines` folder to prevent confusion about supported CI.
99. Replace any leftover “enterprise” claims in README with the simplified intent.
100. Keep only the minimal code necessary to ensure: parse → fetch → evaluate → block/warn.
