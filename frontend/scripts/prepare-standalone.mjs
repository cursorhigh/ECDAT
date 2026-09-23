import { cpSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const standalone = join(root, ".next", "standalone");

if (!existsSync(standalone)) {
  throw new Error("Next standalone output was not generated.");
}

const staticSource = join(root, ".next", "static");
const staticTarget = join(standalone, ".next", "static");
if (existsSync(staticSource)) {
  cpSync(staticSource, staticTarget, { recursive: true, force: true });
}

const publicSource = join(root, "public");
const publicTarget = join(standalone, "public");
if (existsSync(publicSource)) {
  cpSync(publicSource, publicTarget, { recursive: true, force: true });
}

console.log("Standalone frontend assets prepared.");
