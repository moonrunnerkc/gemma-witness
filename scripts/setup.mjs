#!/usr/bin/env node
// First-run bootstrap. Installs frontend deps for the capture and verifier
// apps, builds the Rust workspace, and syncs the mlx sidecar's Python deps.
// Idempotent. Run again any time toolchains move.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function run(label, command, args, opts = {}) {
  return new Promise((res, rej) => {
    process.stdout.write(`\n== ${label} ==\n$ ${command} ${args.join(" ")}\n`);
    const child = spawn(command, args, {
      cwd: opts.cwd ?? repoRoot,
      stdio: "inherit",
      env: { ...process.env, ...(opts.env ?? {}) },
    });
    child.on("exit", (code) => {
      if (code === 0) res();
      else rej(new Error(`${label} failed with exit code ${code}`));
    });
  });
}

const sidecarKind = process.env.GW_SIDECAR_KIND ?? "mlx";

(async () => {
  await run("install capture deps", "pnpm", ["install", "--frozen-lockfile"], {
    cwd: resolve(repoRoot, "apps/capture"),
  });
  await run("install verifier deps", "pnpm", ["install", "--frozen-lockfile"], {
    cwd: resolve(repoRoot, "apps/verifier"),
  });
  await run("build rust workspace", "cargo", ["build", "--workspace", "--locked"]);

  if (sidecarKind === "mlx") {
    await run("sync mlx sidecar python deps", "uv", ["sync", "--frozen"], {
      cwd: resolve(repoRoot, "inference/mlx-sidecar"),
    });
  } else if (sidecarKind === "transformers") {
    await run("sync transformers sidecar python deps", "uv", ["sync", "--frozen"], {
      cwd: resolve(repoRoot, "inference/transformers-sidecar"),
    });
  } else if (sidecarKind === "mistralrs") {
    await run(
      "build check-pinned-binary gate",
      "cargo",
      ["build", "--release", "-p", "check-pinned-binary"],
    );
    process.stdout.write(
      "\nmistralrs binary is not auto-installed. follow inference/mistralrs-sidecar/README.md for the pinned cargo install command.\n",
    );
  } else {
    throw new Error(`unknown GW_SIDECAR_KIND=${sidecarKind}; use mlx, mistralrs, or transformers`);
  }

  process.stdout.write("\nsetup complete. run `pnpm dev` to start the sidecar and capture app.\n");
})().catch((err) => {
  process.stderr.write(`\nsetup failed: ${err.message}\n`);
  process.exit(1);
});
