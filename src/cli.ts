#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import { runAudit, shouldBlockInstall } from "./audit";
import { createRuntimeFromEnv } from "./utils/runtime";

async function main(): Promise<void> {
  const runtime = createRuntimeFromEnv();
  const { cwd, env } = runtime;

  const lockfilePath = env.PNPM_LOCKFILE_PATH
    ? path.resolve(cwd, env.PNPM_LOCKFILE_PATH)
    : path.resolve(cwd, "pnpm-lock.yaml");

  const raw = await fs.readFile(lockfilePath, "utf-8");
  const lockfile = YAML.parse(raw);

  const { report, artifacts } = await runAudit({ lockfile, runtime });

  // eslint-disable-next-line no-console
  console.log(`pnpm-audit-hook: wrote ${artifacts.length} artifact(s)`);

  if (shouldBlockInstall(report, env)) {
    // eslint-disable-next-line no-console
    console.error("pnpm-audit-hook: blocked");
    process.exitCode = 1;
  }
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e?.stack || String(e));
  process.exitCode = 1;
});
