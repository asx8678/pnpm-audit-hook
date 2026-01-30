#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import { loadConfig } from '../src/config';
import { createLogger, envLogLevel } from '../src/utils/logger';
import { runAudit } from '../src/audit';
import { getRegistryUrl } from '../src/utils/env';

function addDays(date: Date, days: number): string {
  const d = new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 10);
}

async function main(): Promise<void> {
  const env = process.env as Record<string, string | undefined>;
  const cwd = process.cwd();
  const logger = createLogger(envLogLevel(env));

  const cfg = await loadConfig({ cwd, env });

  const lockfilePath = path.resolve(cwd, env.PNPM_LOCKFILE_PATH || 'pnpm-lock.yaml');
  const lockRaw = await fs.readFile(lockfilePath, 'utf-8');
  const lockfile = YAML.parse(lockRaw);

  const { report } = await runAudit({ lockfile, runtime: { cwd, env, registryUrl: getRegistryUrl(env) } });

  const expiresDays = env.PNPM_AUDIT_BASELINE_EXPIRES_DAYS ? Number(env.PNPM_AUDIT_BASELINE_EXPIRES_DAYS) : 30;
  const expires = addDays(new Date(), Number.isNaN(expiresDays) ? 30 : expiresDays);

  const allowlist: any[] = [];
  const seen = new Set<string>();

  for (const p of report.packages) {
    for (const f of p.findings) {
      const id = f.id;
      const key = `${p.pkg.name}:${id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      allowlist.push({
        id,
        package: p.pkg.name,
        expires,
        reason: 'Baseline (existing vulnerability at time of adoption)',
        approvedBy: env.PNPM_AUDIT_BASELINE_APPROVED_BY || 'baseline',
      });
    }
  }

  const outPath = path.resolve(cwd, env.PNPM_AUDIT_BASELINE_PATH || '.pnpm-audit-baseline.yaml');
  const out = { allowlist };
  await fs.writeFile(outPath, YAML.stringify(out), 'utf-8');

  logger.info(`Wrote baseline allowlist with ${allowlist.length} entry(s) -> ${outPath}`);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e?.stack || String(e));
  process.exitCode = 1;
});
