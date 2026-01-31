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

const distEntry = path.join(__dirname, 'dist', 'src', 'index.js');

try {
  const mod = require(distEntry);
  if (!mod || typeof mod.createPnpmHooks !== 'function') {
    throw new Error(`Expected an exported createPnpmHooks() from ${distEntry}`);
  }
  module.exports = mod.createPnpmHooks();
} catch (err) {
  const hint = [
    'pnpm-audit-hook: compiled entry not found (or failed to load).',
    `Expected: ${distEntry}`,
    '',
    'Fix:',
    '  1) Run: npm run build',
    '  2) Ensure dist/ is present',
    '',
    `Original error: ${err && err.message ? err.message : String(err)}`,
    '',
    'Docs: https://pnpm.io/pnpmfile',
  ].join('\n');
  throw new Error(hint);
}
