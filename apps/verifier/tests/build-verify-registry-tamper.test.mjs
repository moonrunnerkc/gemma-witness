// Regression coverage for the build-time registry verification entry
// point in `apps/verifier/build-verify-registry.mjs`. The full Sigstore
// happy path is exercised by a real signed envelope at release time;
// these tests cover the failure modes that are reachable without one:
//
//  - Missing bundle when the envelope claims placeholder=false.
//  - Malformed envelope (truncated JSON).
//  - Placeholder envelope returns the typed "placeholder: true" result
//    rather than throwing.
//
// Run: cd apps/verifier && node tests/build-verify-registry-tamper.test.mjs

import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

const REAL_REGISTRY = path.join(__dirname, "..", "..", "..", "inference", "fingerprints");

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERTION FAILED: ${message}`);
  }
}

function makeWorkspace(scratch) {
  // Build-verify-registry.mjs locates its registry via a relative path
  // walk from the verifier source root. To keep these tests hermetic, we
  // construct a tempdir that mirrors the real layout but stops at
  // inference/fingerprints/ and runs the verifier against the temp tree
  // by importing the module with a monkeypatched __dirname-equivalent.
  //
  // The simplest stable shape is to import the module's function with a
  // configurable registry-dir override. We achieve that by reading the
  // module's source and adapting it to take an optional override; in a
  // future revision we can refactor verifyRegistry() to accept the
  // override directly.
  fs.mkdirSync(path.join(scratch, "inference", "fingerprints"), {
    recursive: true,
  });
  // Copy the real registry tree into the scratch dir so the envelope
  // shape stays in sync with whatever is on disk.
  for (const name of fs.readdirSync(REAL_REGISTRY)) {
    const src = path.join(REAL_REGISTRY, name);
    if (fs.statSync(src).isFile()) {
      fs.copyFileSync(src, path.join(scratch, "inference", "fingerprints", name));
    }
  }
}

/**
 * Adapter around the real verifyRegistry. The real function hard-codes
 * the registry path; we read the module source and rewrite that path
 * to point at the scratch tree for the duration of the test. This is
 * heavier than a parameterized API but keeps the production path
 * minimal and matches the static-HTML build's surface.
 */
async function callVerifyWithRegistry(scratchRegistryDir) {
  const realModulePath = path.join(__dirname, "..", "build-verify-registry.mjs");
  const realSrc = fs.readFileSync(realModulePath, "utf-8");
  const patched = realSrc.replace(
    /path\.join\(__dirname,\s*"\.\.",\s*"\.\.",\s*"inference",\s*"fingerprints"\)/,
    JSON.stringify(scratchRegistryDir),
  );
  if (patched === realSrc) {
    throw new Error(
      "test could not patch build-verify-registry.mjs registry path; the path expression was not found. " +
        "either build-verify-registry.mjs was rewritten or this test is out of date.",
    );
  }
  // Write the patched module next to the verifier root so its
  // `import "sigstore"` resolves through the verifier's node_modules
  // tree. The cleanup phase removes it after the import completes.
  const tmpModule = path.join(
    __dirname,
    "..",
    `_patched-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.mjs`,
  );
  fs.writeFileSync(tmpModule, patched, "utf-8");
  try {
    const mod = await import(url.pathToFileURL(tmpModule).href);
    return await mod.verifyRegistry();
  } finally {
    try {
      fs.unlinkSync(tmpModule);
    } catch (e) {
      // Best-effort cleanup; the next test run picks up where we left off.
    }
  }
}

async function runTests() {
  // T1: placeholder envelope returns { placeholder: true } without throwing.
  console.log("--- T1: placeholder envelope returns the typed placeholder result");
  {
    const scratch = fs.mkdtempSync("/tmp/verify-registry-tamper-");
    try {
      makeWorkspace(scratch);
      const result = await callVerifyWithRegistry(
        path.join(scratch, "inference", "fingerprints"),
      );
      assert(result.placeholder === true, "T1: result must declare placeholder=true");
      assert(
        Array.isArray(result.covered_files) && result.covered_files.length > 0,
        "T1: covered_files must be populated",
      );
      console.log("PASS T1");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  }

  // T2: placeholder=false with no bundle on disk throws.
  console.log("--- T2: declared-signed envelope with missing bundle throws");
  {
    const scratch = fs.mkdtempSync("/tmp/verify-registry-tamper-");
    try {
      makeWorkspace(scratch);
      const envPath = path.join(
        scratch,
        "inference",
        "fingerprints",
        "registry-manifest.json",
      );
      const envelope = JSON.parse(fs.readFileSync(envPath, "utf-8"));
      envelope.placeholder = false;
      delete envelope.placeholder_reason;
      envelope.signed_at_utc = "2026-05-15T00:00:00Z";
      fs.writeFileSync(envPath, JSON.stringify(envelope), "utf-8");
      let threw = false;
      try {
        await callVerifyWithRegistry(path.join(scratch, "inference", "fingerprints"));
      } catch (err) {
        threw = true;
        assert(
          /registry-manifest\.sigstore is missing/i.test(String(err.message)),
          `T2: error must name the missing bundle file; got: ${err.message}`,
        );
      }
      assert(threw, "T2: missing bundle must throw");
      console.log("PASS T2");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  }

  // T3: placeholder=false with a malformed (non-JSON) bundle throws via
  // sigstore-verify's parse path.
  console.log("--- T3: declared-signed envelope with malformed bundle throws");
  {
    const scratch = fs.mkdtempSync("/tmp/verify-registry-tamper-");
    try {
      makeWorkspace(scratch);
      const envPath = path.join(
        scratch,
        "inference",
        "fingerprints",
        "registry-manifest.json",
      );
      const envelope = JSON.parse(fs.readFileSync(envPath, "utf-8"));
      envelope.placeholder = false;
      delete envelope.placeholder_reason;
      envelope.signed_at_utc = "2026-05-15T00:00:00Z";
      fs.writeFileSync(envPath, JSON.stringify(envelope), "utf-8");
      fs.writeFileSync(
        path.join(scratch, "inference", "fingerprints", "registry-manifest.sigstore"),
        "not a valid sigstore bundle",
        "utf-8",
      );
      let threw = false;
      try {
        await callVerifyWithRegistry(path.join(scratch, "inference", "fingerprints"));
      } catch (err) {
        threw = true;
        // A malformed bundle file fails either at JSON.parse (the
        // bundle JSON load) or inside sigstore.verify; both paths are
        // build-failure signals and either is acceptable evidence that
        // the gate is in effect.
        const message = String(err?.message ?? err);
        assert(
          /signature did not verify|registry envelope|not valid JSON|JSON.parse|Unexpected token/i.test(
            message,
          ),
          `T3: error must surface bundle-parse or signature-verify failure; got: ${message}`,
        );
      }
      assert(threw, "T3: malformed bundle must throw");
      console.log("PASS T3");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  }

  console.log("\n=== ALL BUILD-VERIFY-REGISTRY TAMPER TESTS PASSED ===");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
