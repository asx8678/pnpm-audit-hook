const esbuild = require("esbuild");
const path = require("path");
const fs = require("fs");

async function bundle() {
  const distDir = path.join(__dirname, "..", "dist");

  // Bundle index.js with all dependencies
  await esbuild.build({
    entryPoints: [path.join(distDir, "index.js")],
    bundle: true,
    platform: "node",
    target: "node18",
    outfile: path.join(distDir, "index.bundled.js"),
    external: ["path", "fs", "node:path", "node:fs", "node:url", "node:zlib"],
    minify: false,
    sourcemap: false,
  });

  // Replace original index.js with bundled version
  fs.copyFileSync(
    path.join(distDir, "index.bundled.js"),
    path.join(distDir, "index.js")
  );
  fs.unlinkSync(path.join(distDir, "index.bundled.js"));

  console.log("Bundled dist/index.js with dependencies");
}

bundle().catch((e) => {
  console.error("Bundle failed:", e);
  process.exit(1);
});
