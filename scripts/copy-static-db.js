const path = require("node:path");
const fs = require("node:fs/promises");

const SRC_DIR = path.join(__dirname, "..", "src", "static-db", "data");
const DEST_DIR = path.join(__dirname, "..", "dist", "static-db", "data");

async function copyStaticDb() {
  await fs.mkdir(path.dirname(DEST_DIR), { recursive: true });
  await fs.cp(SRC_DIR, DEST_DIR, { recursive: true });
}

copyStaticDb().catch((err) => {
  console.error(`Failed to copy static DB: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
