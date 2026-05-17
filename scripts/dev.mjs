#!/usr/bin/env node
// Repo-level dev orchestrator. Issues a per-launch GW_SIDECAR_TOKEN, starts
// the inference sidecar in foreground, starts the Tauri capture app, prefixes
// and colorizes each stream, and tears both down cleanly on Ctrl-C.
//
// Default sidecar is mlx; override with GW_SIDECAR_KIND=mistralrs or
// GW_SIDECAR_KIND=transformers. Loopback bind is enforced by the start.sh
// scripts themselves.
//
// POSIX-only. Each child runs in its own process group so a group SIGTERM
// reaches the deep tree pnpm/tauri/vite/cargo builds out.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const sidecarKind = process.env.GW_SIDECAR_KIND ?? "mlx";
const sidecarHost = process.env.GW_SIDECAR_HOST ?? "127.0.0.1";
const sidecarPort = process.env.GW_SIDECAR_PORT ?? "8080";
const issuedToken = randomBytes(32).toString("hex");

const sharedEnv = {
  ...process.env,
  GW_SIDECAR_TOKEN: issuedToken,
  GW_SIDECAR_HOST: sidecarHost,
  GW_SIDECAR_PORT: sidecarPort,
  GW_SIDECAR_FOREGROUND: "1",
};

const PAINT = {
  sidecar: 36,
  capture: 35,
  "gw-dev": 33,
};

function painter(name) {
  const code = PAINT[name] ?? 37;
  return (line) => `\x1b[${code}m[${name}]\x1b[0m ${line}`;
}

function pipeWithPrefix(stream, name) {
  const paint = painter(name);
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      process.stdout.write(paint(line) + "\n");
    }
  });
  stream.on("end", () => {
    if (buf.length > 0) process.stdout.write(paint(buf) + "\n");
  });
}

const children = [];
let shuttingDown = false;

function shutdown(exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const { name, child } of children) {
    if (child.pid === undefined) continue;
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch (err) {
      if (err.code !== "ESRCH") {
        log("gw-dev", `failed to signal ${name} pid=${child.pid}: ${err.message}`);
      }
    }
  }
  setTimeout(() => process.exit(exitCode), 1500).unref();
}

function log(name, msg) {
  process.stdout.write(painter(name)(msg) + "\n");
}

function spawnChild(name, command, args, opts = {}) {
  const child = spawn(command, args, {
    cwd: opts.cwd ?? repoRoot,
    env: { ...sharedEnv, ...(opts.env ?? {}) },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  children.push({ name, child });
  pipeWithPrefix(child.stdout, name);
  pipeWithPrefix(child.stderr, name);
  child.on("exit", (code, signal) => {
    log("gw-dev", `${name} exited code=${code} signal=${signal ?? "none"}`);
    if (!shuttingDown) shutdown(code ?? 1);
  });
  return child;
}

process.on("SIGINT", () => {
  log("gw-dev", "received SIGINT, shutting down children");
  shutdown(0);
});
process.on("SIGTERM", () => shutdown(0));

log("gw-dev", `issuing per-launch GW_SIDECAR_TOKEN (${issuedToken.slice(0, 8)}…)`);
log("gw-dev", `sidecar kind=${sidecarKind} bind=${sidecarHost}:${sidecarPort}`);

const sidecarScript = `inference/${sidecarKind}-sidecar/start.sh`;
spawnChild("sidecar", sidecarScript, []);
spawnChild("capture", "pnpm", ["tauri", "dev"], {
  cwd: resolve(repoRoot, "apps/capture"),
});

(async () => {
  const url = `http://${sidecarHost}:${sidecarPort}/v1/models`;
  const deadline = Date.now() + 240_000;
  while (!shuttingDown && Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        log("gw-dev", `sidecar reachable at ${url}`);
        return;
      }
    } catch {
      // sidecar not up yet
    }
    await delay(2000);
  }
  if (!shuttingDown) {
    log("gw-dev", `sidecar did not respond on ${url} within 240s; check the [sidecar] logs above`);
  }
})();
