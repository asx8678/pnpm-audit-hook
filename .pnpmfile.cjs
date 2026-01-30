/**
 * pnpm hooks entrypoint.
 *
 * This file is executed by pnpm during dependency resolution.
 * It MUST be CommonJS (pnpm loads `.pnpmfile.cjs` via require()).
 *
 * Implementation detail:
 * - We keep heavy logic in the compiled JS under ./dist
 * - This keeps the hook itself small and avoids loading TS at runtime.
 *
 * If you copy this hook into another repo, adjust the `require(...)` path
 * or install this package as a pnpm "config dependency" and require it by name.
 */
const path = require('node:path');
const fs = require('node:fs');

function safeRequire(p) {
  try {
    return require(p);
  } catch (e) {
    return null;
  }
}

const distEntry = path.join(__dirname, 'dist', 'src', 'index.js');
const mod = fs.existsSync(distEntry) ? safeRequire(distEntry) : null;

if (!mod || typeof mod.createPnpmHooks !== 'function') {
  const hint = [
    'pnpm-audit-hook: compiled entry not found.',
    `Expected: ${distEntry}`,
    '',
    'Fix:',
    '  1) Run: npm run build (or pnpm -C pnpm-audit-hook build)',
    '  2) Ensure dist/ is present (commit dist/ or install as config dependency)',
    '',
    'Docs: https://pnpm.io/pnpmfile',
  ].join('\n');
  throw new Error(hint);
}

module.exports = mod.createPnpmHooks();
