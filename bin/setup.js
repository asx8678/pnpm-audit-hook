#!/usr/bin/env node
const fs = require("fs");
const path = require("path");

const sourceDir = path.resolve(__dirname, "..");
const targetDir = process.cwd();

// Validate target directory has a package.json
if (!fs.existsSync(path.join(targetDir, "package.json"))) {
  console.error("Error: No package.json found in current directory.");
  console.error("Run this command from your project root.");
  process.exit(1);
}

// Check if this is a pnpm project
if (!fs.existsSync(path.join(targetDir, "pnpm-lock.yaml"))) {
  console.warn("Warning: No pnpm-lock.yaml found. This hook only works with pnpm.");
  console.warn("If you use npm or yarn, consider 'npm audit' or 'yarn audit' instead.");
  console.warn("");
}

const filesToCopy = [
  { src: ".pnpmfile.cjs", required: true },
  { src: ".pnpm-audit.yaml", required: false },
];

console.log("Setting up pnpm-audit-hook...\n");

for (const file of filesToCopy) {
  const srcPath = path.join(sourceDir, file.src);
  const destPath = path.join(targetDir, file.src);

  if (fs.existsSync(destPath)) {
    console.log(`  [skip] ${file.src} already exists`);
    continue;
  }

  if (!fs.existsSync(srcPath)) {
    if (file.required) {
      console.error(`  [error] ${file.src} not found in package!`);
      process.exit(1);
    }
    continue;
  }

  // Update .pnpmfile.cjs to point to node_modules
  if (file.src === ".pnpmfile.cjs") {
    let content = fs.readFileSync(srcPath, "utf-8");
    content = content.replace(
      "path.join(__dirname, 'dist', 'index.js')",
      "path.join(__dirname, 'node_modules', 'pnpm-audit-hook', 'dist', 'index.js')"
    );
    fs.writeFileSync(destPath, content);
    console.log(`  [ok] ${file.src} created`);
  } else {
    fs.copyFileSync(srcPath, destPath);
    console.log(`  [ok] ${file.src} copied`);
  }
}

console.log("\nDone! The audit hook will run on every pnpm install.\n");
console.log("Next steps:");
console.log("  1. git add .pnpmfile.cjs .pnpm-audit.yaml");
console.log("  2. Customize .pnpm-audit.yaml for your project");
console.log("  3. Test it with: pnpm add lodash");
console.log("");
console.log("You can also run audits manually: pnpm-audit-scan");
console.log("Add .pnpm-audit-cache/ to .gitignore");
