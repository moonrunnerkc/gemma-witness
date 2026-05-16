import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";
import { verifyRegistry } from "./build-verify-registry.mjs";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

/**
 * Build a single-file verifier HTML from source modules.
 *
 * Inlines all JS (bundled via esbuild), CSS, and known-fingerprints.json into
 * one self-contained HTML file at dist/verify.html.
 *
 * Before bundling, the inference/fingerprints/ registry envelope is
 * verified against its cosign Sigstore bundle. A signature failure
 * aborts the build with a non-zero exit; a placeholder envelope emits a
 * loud warning and proceeds (matching the Rust build.rs behavior in
 * crates/witness-fingerprints/build.rs).
 */
async function build() {
  const outDir = path.join(__dirname, "dist");
  fs.mkdirSync(outDir, { recursive: true });

  // Build-time registry verification. The result is inlined into the
  // HTML as __REGISTRY_VERIFICATION__ so the runtime can surface a
  // "Registry signature" row to the user without redoing the Sigstore
  // dance in the browser. The trust chain is transferred via
  // SHASUMS256.txt covering verify.html.
  const registryVerification = await verifyRegistry();

  // Determinism: every esbuild option below is set explicitly so the
  // output bytes do not depend on environment-derived defaults.
  // `legalComments: "none"` strips banner comments whose order can drift
  // across esbuild versions. `charset: "utf8"` keeps unicode literals as
  // their byte sequences rather than \u-escapes; both choices are valid
  // but only one is reproducible. With every flag pinned, the SHA-256 of
  // dist/verify.html is asserted against apps/verifier/expected-output-hash.txt
  // in CI and any drift surfaces as a build failure rather than as a
  // mystery release-artifact mismatch.
  const esbuild = await import("esbuild");
  const result = await esbuild.build({
    entryPoints: [path.join(__dirname, "verify.ts")],
    bundle: true,
    write: false,
    format: "iife",
    target: "es2022",
    minify: true,
    minifyWhitespace: true,
    minifySyntax: true,
    minifyIdentifiers: true,
    treeShaking: true,
    legalComments: "none",
    charset: "utf8",
    keepNames: false,
    sourcemap: false,
  });

  const jsBundle = result.outputFiles[0].text;

  // Inline CSS.
  const cssPath = path.join(__dirname, "src", "style.css");
  const css = fs.readFileSync(cssPath, "utf-8");

  // Inline known-fingerprints.json as a JS variable so the verifier has it
  // at runtime without an external request.
  const fpPath = path.join(__dirname, "known-fingerprints.json");
  const fpJson = fs.readFileSync(fpPath, "utf-8");

  // Same treatment for trusted-signers.json. See audit finding V-1.
  const trustedPath = path.join(__dirname, "trusted-signers.json");
  const trustedJson = fs.readFileSync(trustedPath, "utf-8");

  const templatePath = path.join(__dirname, "index.html");
  let html = fs.readFileSync(templatePath, "utf-8");

  html = html.replace("/*INLINE_CSS*/", css);
  html = html.replace(
    "/*INLINE_FINGERPRINTS*/ null",
    fpJson
  );
  html = html.replace(
    "/*INLINE_TRUSTED_SIGNERS*/ null",
    trustedJson
  );
  html = html.replace(
    "/*INLINE_REGISTRY_VERIFICATION*/ null",
    JSON.stringify(registryVerification, null, 2),
  );
  html = html.replace("/*INLINE_JS*/", jsBundle);

  const outPath = path.join(outDir, "verify.html");
  fs.writeFileSync(outPath, html, "utf-8");

  // Evidence: byte size.
  const stats = fs.statSync(outPath);
  console.log(`Built dist/verify.html: ${stats.size} bytes`);

  // Evidence: no external fetches.
  const htmlText = fs.readFileSync(outPath, "utf-8");
  const externalRefs =
    [...htmlText.matchAll(/(?:src|href)="(https?:\/\/[^"]+)"/g)].map(
      (m) => m[1]
    );
  if (externalRefs.length > 0) {
    console.error("ERROR: external references found:", externalRefs);
    process.exit(1);
  }
  const networkCalls =
    [...htmlText.matchAll(/\bfetch\s*\(/g)].length +
    [...htmlText.matchAll(/\bXMLHttpRequest\b/g)].length +
    [...htmlText.matchAll(/\bimportScripts\b/g)].length;
  if (networkCalls > 0) {
    console.error("ERROR: runtime network calls found in bundled output");
    process.exit(1);
  }
  const cspMeta =
    /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*default-src 'none'[^"]*"/i;
  if (!cspMeta.test(htmlText)) {
    console.error(
      "ERROR: bundled verifier is missing the Content-Security-Policy meta tag. "
        + "the directive `default-src 'none'` must survive inlining; "
        + "check that index.html still carries it and the inlining step did not strip the <meta>.",
    );
    process.exit(1);
  }
  console.log("Static checks passed: no external src/href, no fetch/XHR/importScripts, CSP meta present.");

  // Reproducibility gate. The expected hash is committed to the repo; CI
  // re-runs this build and asserts the bytes match. Drift surfaces here
  // rather than as a "release artifact does not match the rebuild"
  // mystery weeks later. When a real intentional change lands (a noble
  // bump, a verifier code change), update apps/verifier/expected-output-hash.txt
  // in the same commit.
  const expectedHashPath = path.join(__dirname, "expected-output-hash.txt");
  if (fs.existsSync(expectedHashPath)) {
    const { createHash } = await import("node:crypto");
    const actualHash = createHash("sha256").update(htmlText).digest("hex");
    const expectedHash = fs.readFileSync(expectedHashPath, "utf-8").trim();
    if (expectedHash && expectedHash !== "PLACEHOLDER") {
      if (actualHash !== expectedHash) {
        const drift = process.env.GW_VERIFIER_ALLOW_HASH_DRIFT === "1";
        const msg = `verifier output hash drift: expected ${expectedHash}, got ${actualHash}.`;
        if (drift) {
          console.warn(`WARNING: ${msg} (GW_VERIFIER_ALLOW_HASH_DRIFT=1; not failing)`);
        } else {
          console.error(`ERROR: ${msg}`);
          console.error(
            "if this change is intentional, update apps/verifier/expected-output-hash.txt with the new hash in the same commit. " +
            "if this change is unexpected, the build is non-reproducible and the cause must be diagnosed before tagging.",
          );
          process.exit(1);
        }
      } else {
        console.log(`Reproducibility check passed: SHA-256 ${actualHash}`);
      }
    } else {
      console.log(`Reproducibility check skipped (expected hash is placeholder). Actual SHA-256 ${actualHash}`);
    }
  }
}

build().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
