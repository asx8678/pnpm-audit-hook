#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import { loadConfig } from '../src/config';
import { createLogger, envLogLevel } from '../src/utils/logger';
import { MemoryCache } from '../src/cache/memory-cache';
import { FileCache } from '../src/cache/file-cache';
import { LayeredCache } from '../src/cache/layered-cache';
import { extractPackagesFromLockfile } from '../src/utils/lockfile';
import { aggregateVulnerabilities } from '../src/databases/aggregator';
import { getRegistryUrl } from '../src/utils/env';

async function main(): Promise<void> {
  const env = process.env as Record<string, string | undefined>;
  const cwd = process.cwd();
  const logger = createLogger(envLogLevel(env));
  const cfg = await loadConfig({ cwd, env });

  const lockfilePath = path.resolve(cwd, env.PNPM_LOCKFILE_PATH || 'pnpm-lock.yaml');
  const raw = await fs.readFile(lockfilePath, 'utf-8');
  const lockfile = YAML.parse(raw);

  const { packages } = extractPackagesFromLockfile(lockfile);

  const mem = new MemoryCache();
  const fileDir = path.resolve(cwd, cfg.cache?.dir ?? '.pnpm-audit-cache');
  const file = new FileCache({ dir: fileDir, allowStale: true });
  const cache = new LayeredCache([mem, file]);

  logger.info(`Warming cache for ${packages.length} package(s) into ${fileDir}`);

  const agg = await aggregateVulnerabilities(packages, {
    cfg,
    env,
    cache,
    logger,
    registryUrl: getRegistryUrl(env),
    offline: false,
    networkPolicy: 'fail-open',
  });

  logger.info(`Done. Sources: ${Object.entries(agg.sources).map(([k, v]) => `${k}=${v.ok ? 'ok' : 'err'}`).join(', ')}`);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e?.stack || String(e));
  process.exitCode = 1;
});
