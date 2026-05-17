#!/usr/bin/env node
// Repo-level dev orchestrator.
//
// The Tauri capture app spawns the inference sidecar itself (see
// apps/capture/src-tauri/src/sidecar.rs), issues GW_SIDECAR_TOKEN before
// any frontend code runs, and kills the child on RunEvent::ExitRequested.
// So `pnpm dev` from the repo root is effectively `pnpm tauri dev` with two
// extras:
//
//   1. it issues a per-launch GW_SIDECAR_TOKEN here so even a `pnpm dev`
//      followed by a `cargo run -p witness-cli` in another terminal can
//      reuse the same token without re-exporting it manually
//   2. it cleanly forwards SIGINT to the Tauri process group so the
//      sidecar shuts down with the app
//
// Override the sidecar backend with GW_SIDECAR_KIND=mistralrs|transformers.
// POSIX-only.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const sidecarKind = process.env.GW_SIDECAR_KIND ?? "mlx";
const sidecarHost = process.env.GW_SIDECAR_HOST ?? "127.0.0.1";
const sidecarPort = process.env.GW_SIDECAR_PORT ?? "8080";
const token = process.env.GW_SIDECAR_TOKEN ?? randomBytes(32).toString("hex");

const env = {
  ...process.env,
  GW_SIDECAR_TOKEN: token,
  GW_SIDECAR_KIND: sidecarKind,
  GW_SIDECAR_HOST: sidecarHost,
  GW_SIDECAR_PORT: sidecarPort,
};

console.log(`[gw-dev] sidecar kind=${sidecarKind} bind=${sidecarHost}:${sidecarPort}`);
console.log(`[gw-dev] GW_SIDECAR_TOKEN issued (${token.slice(0, 8)}…) and exported to tauri dev`);
console.log(`[gw-dev] the capture app will spawn the sidecar itself; logs interleave below`);

const child = spawn("pnpm", ["tauri", "dev"], {
  cwd: resolve(repoRoot, "apps/capture"),
  env,
  stdio: "inherit",
  detached: true,
});

let shuttingDown = false;
function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch (err) {
    if (err.code !== "ESRCH") {
      console.error(`[gw-dev] failed to signal tauri group: ${err.message}`);
    }
  }
  setTimeout(() => process.exit(code), 1500).unref();
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

child.on("exit", (code, signal) => {
  console.log(`[gw-dev] tauri dev exited code=${code} signal=${signal ?? "none"}`);
  process.exit(code ?? 0);
});
