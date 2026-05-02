/**
 * Post-build: register CLI commands globally via pnpm link.
 * 
 * Only runs in the source repo (detected by presence of src/ directory).
 * Silently skipped in CI or when permissions prevent global linking.
 */
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// Only link globally when in source repo (not when installed as a dependency)
const srcDir = path.join(__dirname, "..", "src");
if (!fs.existsSync(srcDir)) {
  process.exit(0);
}

// Skip in CI environments (global linking is not useful there)
if (process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true" || process.env.TF_BUILD === "True") {
  process.exit(0);
}

try {
  execSync("pnpm link --global", {
    cwd: path.join(__dirname, ".."),
    stdio: "pipe",
  });
  console.log("Registered CLI commands globally: pnpm-audit-scan, pnpm-audit-setup");
} catch {
  // Not fatal — user can still use: pnpm exec pnpm-audit-scan
  // Common reasons: no global pnpm, permission denied, etc.
  console.log("Tip: Run 'pnpm link --global' to register pnpm-audit-scan globally");
}
