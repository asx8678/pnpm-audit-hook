#!/usr/bin/env node
const fs = require("fs");
const path = require("path");

const sourceDir = path.resolve(__dirname, "..");
const targetDir = process.cwd();

const filesToCopy = [
  { src: ".pnpmfile.cjs", required: true },
  { src: ".pnpm-audit.yaml", required: false },
];

console.log("Setting up pnpm-audit-hook...\n");

for (const file of filesToCopy) {
  const srcPath = path.join(sourceDir, file.src);
  const destPath = path.join(targetDir, file.src);

  if (fs.existsSync(destPath)) {
    console.log(`  ⏭  ${file.src} already exists, skipping`);
    continue;
  }

  if (!fs.existsSync(srcPath)) {
    if (file.required) {
      console.error(`  ❌ ${file.src} not found in package!`);
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
    console.log(`  ✅ ${file.src} created`);
  } else {
    fs.copyFileSync(srcPath, destPath);
    console.log(`  ✅ ${file.src} copied`);
  }
}

console.log("\n✨ Done! The audit hook will run on every pnpm install.\n");
console.log("Test it with: pnpm add lodash");
