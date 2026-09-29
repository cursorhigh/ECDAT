import { spawn } from "node:child_process";
import { join } from "node:path";

import { resolveStandaloneAppDir } from "./standalone-paths.mjs";

const args = process.argv.slice(2);
let port = process.env.PORT || "3000";

for (let index = 0; index < args.length; index += 1) {
  const value = args[index];
  if (value === "-p" || value === "--port") {
    port = args[index + 1] || port;
    index += 1;
  } else if (value.startsWith("--port=")) {
    port = value.slice("--port=".length);
  }
}

// Resolves the real location instead of assuming `.next/standalone/server.js`,
// which is where Next puts it only when the tracing root is the app itself.
// Exits with a readable message rather than a bare MODULE_NOT_FOUND stack.
let appDir;
try {
  appDir = resolveStandaloneAppDir(process.cwd());
} catch (error) {
  console.error(`[start-standalone] ${error.message}`);
  process.exit(1);
}

const server = join(appDir, "server.js");
console.log(`[start-standalone] serving ${server} on port ${port}`);

/**
 * Which interface to bind.
 *
 * This deliberately does NOT read `process.env.HOSTNAME`. In Git Bash that
 * variable is set to the machine's own name, so passing it through made Next
 * resolve and bind the machine's LAN address: the server came up as
 * `http://ROG-ZEPHYRUS-14:3000` while both http://localhost:3000 and
 * http://127.0.0.1:3000 were refused. Dev mode was unaffected because
 * `next dev` picks its own bind address, so the failure only ever showed up in
 * preview -- which is exactly where you go to check a build.
 *
 * `0.0.0.0` serves loopback and the LAN, so both spellings work. Set
 * `BIND_HOST=127.0.0.1` to keep the preview on this machine only.
 */
const bindHost = process.env.BIND_HOST || "0.0.0.0";

const child = spawn(process.execPath, [server], {
  // Next's standalone server resolves static assets relative to its own
  // directory, so the cwd has to be appDir rather than the repo root.
  cwd: appDir,
  env: {
    ...process.env,
    PORT: String(port),
    HOSTNAME: bindHost
  },
  stdio: "inherit"
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 0);
});
