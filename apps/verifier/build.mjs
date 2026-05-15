import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

/**
 * Build a single-file verifier HTML from source modules.
 *
 * Inlines all JS (bundled via esbuild), CSS, and known-fingerprints.json into
 * one self-contained HTML file at dist/verify.html.
 */
async function build() {
  const outDir = path.join(__dirname, "dist");
  fs.mkdirSync(outDir, { recursive: true });

  // Bundle TypeScript entry point into a single JS string.
  const esbuild = await import("esbuild");
  const result = await esbuild.build({
    entryPoints: [path.join(__dirname, "verify.ts")],
    bundle: true,
    write: false,
    format: "iife",
    target: "es2022",
    minify: true,
    treeShaking: true,
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
}

build().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
