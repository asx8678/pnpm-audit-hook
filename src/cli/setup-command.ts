/**
 * Setup command handler for pnpm-audit-setup.
 *
 * Copies hook files and config to the target project.
 */

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

/**
 * Detect the installed pnpm major version.
 *
 * @returns Pnpm major version number (defaults to 8)
 */
function detectPnpmVersion(): number {
  try {
    const version = execSync("pnpm --version", { encoding: "utf-8" }).trim();
    const match = version.match(/^(\d+)\./);
    if (match && match[1]) {
      return parseInt(match[1], 10);
    }
    return 8;
  } catch {
    console.warn("Warning: Could not detect pnpm version. Assuming v8.");
    return 8;
  }
}

/**
 * Run the setup command.
 *
 * @param sourceDir - Root directory of the pnpm-audit-hook package
 * @returns Process exit code
 */
export function runSetupCommand(sourceDir?: string): number {
  const resolvedSourceDir = sourceDir ?? path.join(__dirname, "..");
  const targetDir = process.cwd();

  // Validate target directory has a package.json
  if (!fs.existsSync(path.join(targetDir, "package.json"))) {
    console.error("Error: No package.json found in current directory.");
    console.error("Run this command from your project root.");
    return 1;
  }

  // Check if this is a pnpm project
  if (!fs.existsSync(path.join(targetDir, "pnpm-lock.yaml"))) {
    console.warn("Warning: No pnpm-lock.yaml found. This hook only works with pnpm.");
    console.warn("If you use npm or yarn, consider 'npm audit' or 'yarn audit' instead.");
    console.warn("");
  }

  const pnpmVersion = detectPnpmVersion();
  const isPnpm9Plus = pnpmVersion >= 9;

  console.log(`Detected pnpm v${pnpmVersion}`);
  console.log(`Using ${isPnpm9Plus ? "ESM hook (.pnpmfile.mjs)" : "CommonJS hook (.pnpmfile.cjs)"}\n`);

  const hookFile = isPnpm9Plus ? ".pnpmfile.mjs" : ".pnpmfile.cjs";
  const filesToCopy: Array<{ src: string; required: boolean; target: string }> = [
    { src: hookFile, required: true, target: hookFile },
    { src: ".pnpm-audit.yaml", required: false, target: ".pnpm-audit.yaml" },
  ];

  if (isPnpm9Plus) {
    filesToCopy.push({ src: ".pnpmfile.cjs", required: false, target: ".pnpmfile.cjs" });
  } else {
    filesToCopy.push({ src: ".pnpmfile.mjs", required: false, target: ".pnpmfile.mjs" });
  }

  console.log("Setting up pnpm-audit-hook...\n");

  for (const file of filesToCopy) {
    const srcPath = path.join(resolvedSourceDir, file.src);
    const destPath = path.join(targetDir, file.target);

    if (fs.existsSync(destPath)) {
      console.log(`  [skip] ${file.target} already exists`);
      continue;
    }

    if (!fs.existsSync(srcPath)) {
      if (file.required) {
        console.error(`  [error] ${file.src} not found in package!`);
        return 1;
      }
      continue;
    }

    let content = fs.readFileSync(srcPath, "utf-8");

    if (file.src === ".pnpmfile.cjs") {
      content = content.replace(
        "path.join(__dirname, 'dist', 'index.js')",
        "path.join(__dirname, 'node_modules', 'pnpm-audit-hook', 'dist', 'index.js')",
      );
    }

    fs.writeFileSync(destPath, content);
    console.log(`  [ok] ${file.target} created`);
  }

  console.log("\nDone! The audit hook will run on every pnpm install.\n");
  console.log("Next steps:");
  console.log(`  1. git add ${hookFile} .pnpm-audit.yaml`);
  console.log("  2. Customize .pnpm-audit.yaml for your project");
  console.log("  3. Test it with: pnpm add lodash");
  console.log("");

  if (isPnpm9Plus) {
    console.log("\u{1F4CB} pnpm 9+ Migration Guide:");
    console.log("  - We've created .pnpmfile.mjs (ESM format) for pnpm 9+");
    console.log("  - The legacy .pnpmfile.cjs is also included as fallback");
    console.log("  - If you have an existing .pnpmfile.cjs, you can remove it");
    console.log("  - The new hook uses preResolution instead of afterAllResolved");
    console.log("");
  }

  console.log("Run audits manually:");
  console.log("  pnpm exec pnpm-audit-scan          # from this project");
  console.log("  pnpm-audit-scan                     # if installed globally");
  console.log("Add .pnpm-audit-cache/ to .gitignore");

  return 0;
}
