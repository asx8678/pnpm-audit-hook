/* eslint-disable no-console */
const tl = require('azure-pipelines-task-lib/task');
const cp = require('child_process');

async function run() {
  try {
    const severityThreshold = tl.getInput('severityThreshold', false) || 'high';
    const failOnWarn = tl.getBoolInput('failOnWarn', false);
    const offlineMode = tl.getBoolInput('offlineMode', false);

    tl.setVariable('PNPM_AUDIT_SEVERITY_THRESHOLD', severityThreshold);
    tl.setVariable('PNPM_AUDIT_FAIL_ON_WARN', String(failOnWarn));
    tl.setVariable('PNPM_AUDIT_OFFLINE_MODE', String(offlineMode));
    tl.setVariable('PNPM_AUDIT_ENABLED', 'true');

    // Run the CLI from the repository (expects `npm ci` / `pnpm i` ran already or tool available)
    const cmd = process.platform === 'win32' ? 'node' : 'node';
    const args = ['node_modules/.bin/pnpm-audit-hook'];

    tl.debug(`Running: ${cmd} ${args.join(' ')}`);

    const res = cp.spawnSync(cmd, args, { stdio: 'inherit' });
    if (res.status !== 0) {
      tl.setResult(tl.TaskResult.Failed, `pnpm audit failed with exit code ${res.status}`);
      return;
    }

    tl.setResult(tl.TaskResult.Succeeded, 'pnpm audit completed');
  } catch (err) {
    tl.setResult(tl.TaskResult.Failed, err.message || String(err));
  }
}

run();
