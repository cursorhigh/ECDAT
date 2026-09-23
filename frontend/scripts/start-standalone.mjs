import { spawn } from "node:child_process";
import { join } from "node:path";

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

const server = join(process.cwd(), ".next", "standalone", "server.js");
const child = spawn(process.execPath, [server], {
  env: {
    ...process.env,
    PORT: String(port),
    HOSTNAME: process.env.HOSTNAME || "127.0.0.1"
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
