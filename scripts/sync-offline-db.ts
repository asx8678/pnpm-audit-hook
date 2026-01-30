#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import YAML from 'yaml';
import { loadConfig } from '../src/config';
import { createLogger, envLogLevel } from '../src/utils/logger';
import { MemoryCache } from '../src/cache/memory-cache';
import { FileCache } from '../src/cache/file-cache';
import { LayeredCache } from '../src/cache/layered-cache';
import { extractPackagesFromLockfile } from '../src/utils/lockfile';
import { aggregateVulnerabilities } from '../src/databases/aggregator';
import { getRegistryUrl } from '../src/utils/env';

async function hashFile(filePath: string): Promise<string> {
  const buf = await fs.readFile(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function listFilesRecursive(dir: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(d: string): Promise<void> {
    const entries = await fs.readdir(d, { withFileTypes: true });
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else out.push(p);
    }
  }
  await walk(dir);
  return out;
}

/**
 * Creates an "offline DB" snapshot by pre-warming the cache directory for the
 * packages in pnpm-lock.yaml. The snapshot can be copied to an air-gapped agent and used with:
 *
 *   PNPM_AUDIT_OFFLINE_MODE=true
 *   PNPM_AUDIT_OFFLINE_DB_PATH=/path/to/snapshot
 */
async function main(): Promise<void> {
  const env = process.env as Record<string, string | undefined>;
  const cwd = process.cwd();
  const logger = createLogger(envLogLevel(env));

  const cfg = await loadConfig({ cwd, env });

  const lockfilePath = path.resolve(cwd, env.PNPM_LOCKFILE_PATH || 'pnpm-lock.yaml');
  const raw = await fs.readFile(lockfilePath, 'utf-8');
  const lockfile = YAML.parse(raw);

  const { packages } = extractPackagesFromLockfile(lockfile);

  const outDir = path.resolve(cwd, env.PNPM_AUDIT_OFFLINE_DB_PATH || 'pnpm-audit-offline-db');
  await fs.mkdir(outDir, { recursive: true });

  const mem = new MemoryCache();
  const file = new FileCache({ dir: outDir, allowStale: true });
  const cache = new LayeredCache([mem, file]);

  logger.info(`Creating offline cache snapshot for ${packages.length} package(s) in ${outDir}`);

  const agg = await aggregateVulnerabilities(packages, {
    cfg,
    env,
    cache,
    logger,
    registryUrl: getRegistryUrl(env),
    offline: false,
    networkPolicy: 'fail-open',
  });

  // Manifest with file hashes for integrity. (Sign externally if required.)
  const files = await listFilesRecursive(outDir);
  const hashes: Record<string, string> = {};
  for (const f of files) {
    if (f.endsWith('.tmp')) continue;
    hashes[path.relative(outDir, f)] = await hashFile(f);
  }

  const manifest = {
    createdAt: new Date().toISOString(),
    registryUrl: getRegistryUrl(env),
    packageCount: packages.length,
    sources: agg.sources,
    fileCount: Object.keys(hashes).length,
    hashes,
  };

  const manifestPath = path.join(outDir, 'offline-db-manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');

  logger.info(`Wrote manifest: ${manifestPath}`);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e?.stack || String(e));
  process.exitCode = 1;
});
