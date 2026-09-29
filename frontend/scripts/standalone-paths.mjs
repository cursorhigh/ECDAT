import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * Find the runnable app directory inside Next's `output: "standalone"` bundle.
 *
 * Next does not guarantee a flat layout. When it infers an `outputFileTracingRoot`
 * above the app (this repo has a `package-lock.json` one level above `frontend`),
 * the real entrypoint nests at `.next/standalone/<app>/server.js` and the static
 * assets have to be copied *into that same directory*, not into `standalone/`.
 *
 * Hardcoding either path is what broke `npm start` with MODULE_NOT_FOUND, so
 * both scripts resolve the location through here instead.
 *
 * Returns the directory that contains `server.js` -- use it as the server's cwd.
 */
export function resolveStandaloneAppDir(root = process.cwd()) {
  const standalone = join(root, ".next", "standalone");

  if (!existsSync(standalone)) {
    throw new Error(
      `Next standalone output not found at ${standalone}. Run \`npm run build\` first.`
    );
  }

  // The expected layout: server.js sits directly in standalone/.
  const flat = join(standalone, "server.js");
  if (existsSync(flat)) return standalone;

  // Otherwise look one level deep. node_modules is skipped so the bundled copy
  // of Next's own internals can never be mistaken for the app entrypoint.
  const candidates = readdirSync(standalone, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name !== "node_modules")
    .map((entry) => join(standalone, entry.name))
    .filter((dir) => existsSync(join(dir, "server.js")));

  if (candidates.length === 1) return candidates[0];

  throw new Error(
    `Could not locate server.js in ${standalone}. Looked for it at the top level ` +
      `and one directory deep. Run \`npm run build\` to regenerate the output.`
  );
}
