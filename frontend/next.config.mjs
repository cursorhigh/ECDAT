import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const appDir = dirname(fileURLToPath(import.meta.url));

const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  // Pin the tracing root to this app directory.
  //
  // Left unset, Next infers it from the nearest workspace root, and this repo
  // has a `package-lock.json` one level *above* `frontend`. The standalone
  // output then nests at `.next/standalone/frontend/server.js` instead of
  // `.next/standalone/server.js`, so `npm start` fails with MODULE_NOT_FOUND
  // even though the build itself succeeded. Pinning it keeps the flat layout
  // that scripts/standalone-paths.mjs and the asset copy both expect.
  outputFileTracingRoot: appDir,
  poweredByHeader: false,
  trailingSlash: false,
  skipTrailingSlashRedirect: true
};

export default nextConfig;
