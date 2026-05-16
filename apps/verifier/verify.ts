import { verifyBundle as verifyBundleLogic } from "./src/verify-logic";
import type {
  KnownFingerprints,
  TrustedSigners,
  RegistryVerification,
} from "./src/types";
import { renderResult } from "./src/render-result";

// re-export for test harnesses and programmatic use
export { verifyBundleLogic as verifyBundle };

// ---------------------------------------------------------------------------
// DOM wiring
// ---------------------------------------------------------------------------

function init(): void {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input") as HTMLInputElement | null;
  const results = document.getElementById("results");

  if (!dropZone || !fileInput || !results) {
    console.error("verifier: required DOM elements are missing");
    return;
  }

  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    dropZone.classList.add("drag-over");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
  });

  dropZone.addEventListener("drop", (ev) => {
    ev.preventDefault();
    dropZone.classList.remove("drag-over");
    const files = ev.dataTransfer?.files;
    if (files && files.length > 0) {
      handleFile(files[0], results);
    }
  });

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) {
      handleFile(file, results);
    }
  });
}

async function handleFile(file: File, results: HTMLElement): Promise<void> {
  results.innerHTML = "";
  const pending = document.createElement("div");
  pending.className = "row pending";
  pending.innerHTML = `<div class="row-name">Verifying ${escapeHtml(file.name)}...</div><div class="row-status">Pending</div>`;
  results.appendChild(pending);

  let buffer: ArrayBuffer;
  try {
    buffer = await file.arrayBuffer();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    renderResult(results, {
      ok: false,
      checks: [],
      manifest: null,
      error: `could not read file: ${message}. ensure the file is accessible and try again.`,
    });
    return;
  }

  let known: KnownFingerprints;
  let trusted: TrustedSigners;
  let registry: RegistryVerification | null;
  try {
    known = loadKnownFingerprints();
    trusted = loadTrustedSigners();
    registry = loadRegistryVerification();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    renderResult(results, {
      ok: false,
      checks: [],
      manifest: null,
      error: `could not load verifier trust anchors: ${message}`,
    });
    return;
  }

  try {
    const result = await verifyBundleLogic(buffer, known, trusted, registry);
    renderResult(results, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    renderResult(results, {
      ok: false,
      checks: [],
      manifest: null,
      error: `verifier raised an unexpected error: ${message}. the bundle may be malformed in a way the verifier did not anticipate.`,
    });
  }
}

function loadKnownFingerprints(): KnownFingerprints {
  const raw: unknown = (window as unknown as Record<string, unknown>)
    .__KNOWN_FINGERPRINTS__;
  if (
    typeof raw !== "object" ||
    raw === null ||
    !Array.isArray((raw as Record<string, unknown>).fingerprints)
  ) {
    throw new Error(
      "known-fingerprints data is missing or malformed in the verifier bundle. rebuild the verifier or check apps/verifier/known-fingerprints.json.",
    );
  }
  return raw as KnownFingerprints;
}

function loadTrustedSigners(): TrustedSigners {
  const raw: unknown = (window as unknown as Record<string, unknown>)
    .__TRUSTED_SIGNERS__;
  if (
    typeof raw !== "object" ||
    raw === null ||
    !Array.isArray((raw as Record<string, unknown>).signers)
  ) {
    throw new Error(
      "trusted-signers data is missing or malformed in the verifier bundle. rebuild the verifier or check apps/verifier/trusted-signers.json.",
    );
  }
  return raw as TrustedSigners;
}

function loadRegistryVerification(): RegistryVerification | null {
  const raw: unknown = (window as unknown as Record<string, unknown>)
    .__REGISTRY_VERIFICATION__;
  if (raw === null || raw === undefined) {
    return null;
  }
  if (typeof raw !== "object") {
    throw new Error(
      "registry verification data is malformed in the verifier bundle. rebuild via apps/verifier/build.mjs.",
    );
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.placeholder !== "boolean" || !Array.isArray(obj.covered_files)) {
    throw new Error(
      "registry verification data is missing required fields. rebuild via apps/verifier/build.mjs.",
    );
  }
  return raw as RegistryVerification;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
}
