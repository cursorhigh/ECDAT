import { cpSync, existsSync } from "node:fs";
import { join } from "node:path";

import { resolveStandaloneAppDir } from "./standalone-paths.mjs";

const root = process.cwd();

// Throws with an actionable message when the bundle is missing or unrecognised.
const appDir = resolveStandaloneAppDir(root);

/**
 * Standalone output ships only the server. `.next/static` and `public` are
 * deliberately left behind, so they must be copied next to server.js or the page
 * renders with no CSS or JS.
 *
 * They are copied into `appDir` (not `standalone/`) because that is the
 * directory the server runs from, and Next resolves static assets relative to it.
 */
for (const [label, source, target] of [
  ["static assets", join(root, ".next", "static"), join(appDir, ".next", "static")],
  ["public files", join(root, "public"), join(appDir, "public")]
]) {
  if (!existsSync(source)) {
    console.log(`No ${label} to copy (${source} not present).`);
    continue;
  }
  cpSync(source, target, { recursive: true, force: true });
  console.log(`Copied ${label} into ${target}`);
}

console.log("Standalone frontend assets prepared.");
