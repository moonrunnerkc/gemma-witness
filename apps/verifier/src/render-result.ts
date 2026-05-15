import type {
  AmendsReference,
  AudioFingerprint,
  InferenceParameters,
  Manifest,
  PassParameters,
  VerificationResult,
} from "./types";

/**
 * Render a {@link VerificationResult} into the DOM.
 *
 * @param container - The DOM element that will host the result rows.
 * @param result - The result to render.
 */
export function renderResult(
  container: HTMLElement,
  result: VerificationResult,
): void {
  container.innerHTML = "";

  if (result.error) {
    const errorDiv = document.createElement("div");
    errorDiv.className = "row fail";
    errorDiv.innerHTML = `<div class="row-name">Bundle error</div><div class="row-status">Failed</div>`;
    const drill = document.createElement("div");
    drill.className = "drilldown";
    drill.textContent = result.error;
    errorDiv.appendChild(drill);
    container.appendChild(errorDiv);
    return;
  }

  for (const check of result.checks) {
    const row = document.createElement("div");
    row.className = `row ${check.passed ? "pass" : "fail"}`;
    row.innerHTML = `<div class="row-name">${escapeHtml(check.name)}</div><div class="row-status">${check.passed ? "Verified" : "Failed"}</div>`;

    if (check.details.length > 0) {
      const drill = document.createElement("div");
      drill.className = "drilldown";
      drill.textContent = check.details.join("\n");
      row.appendChild(drill);
    }

    container.appendChild(row);
  }

  const summary = document.createElement("div");
  summary.className = `row ${result.ok ? "pass" : "fail"}`;
  summary.innerHTML = `<div class="row-name">Overall</div><div class="row-status">${result.ok ? "All checks passed" : "Verification failed"}</div>`;
  container.appendChild(summary);

  if (result.manifest) {
    appendOptionalRows(container, result.manifest);
  }
}

/**
 * Surface the optional manifest fields (amends pointer, inference parameters,
 * audio fingerprint) as read-only advisory rows. None of these gate the
 * overall pass/fail outcome; the row class stays `advisory` so the CSS does
 * not paint them with a verification colour.
 */
function appendOptionalRows(container: HTMLElement, manifest: Manifest): void {
  if (manifest.amends) {
    container.appendChild(renderAmendsRow(manifest.amends));
  }

  const fingerprint =
    manifest.assertions["gemma.witness.audio_fingerprint"];
  if (fingerprint) {
    container.appendChild(renderAudioFingerprintRow(fingerprint));
  }

  const params = manifest.assertions["gemma.witness.inference_parameters"];
  if (params) {
    container.appendChild(renderInferenceParametersRow(params));
  }
}

function renderAmendsRow(amends: AmendsReference): HTMLElement {
  const row = document.createElement("div");
  row.className = "row advisory";
  row.innerHTML = `<div class="row-name">Amends prior bundle</div><div class="row-status">Reference</div>`;
  const drill = document.createElement("div");
  drill.className = "drilldown";
  drill.textContent =
    `original_bundle_id:        ${amends.original_bundle_id}\n` +
    `original_manifest_sha256:  ${amends.original_manifest_sha256}\n` +
    `original_signer_key_id:    ${amends.original_signer_key_id}\n` +
    `reason:                    ${amends.reason}`;
  row.appendChild(drill);
  return row;
}

function renderAudioFingerprintRow(fp: AudioFingerprint): HTMLElement {
  const row = document.createElement("div");
  row.className = "row advisory";
  row.innerHTML = `<div class="row-name">Audio fingerprint (${escapeHtml(fp.algorithm)})</div><div class="row-status">Advisory</div>`;
  const drill = document.createElement("div");
  drill.className = "drilldown";
  drill.textContent = `value: ${fp.value}\nnote:  ${fp.note}`;
  row.appendChild(drill);
  return row;
}

function renderInferenceParametersRow(params: InferenceParameters): HTMLElement {
  const row = document.createElement("div");
  row.className = "row advisory";
  row.innerHTML = `<div class="row-name">Inference parameters</div><div class="row-status">Advisory</div>`;
  const drill = document.createElement("div");
  drill.className = "drilldown";

  const passNames = Object.keys(params.passes).sort();
  const lines: string[] = [];
  for (const name of passNames) {
    lines.push(`${name}:`);
    lines.push(formatPass(params.passes[name]));
  }
  lines.push(`sampling_seed: ${params.sampling_seed === null ? "none" : params.sampling_seed}`);
  lines.push(`note: ${params.note}`);
  drill.textContent = lines.join("\n");
  row.appendChild(drill);
  return row;
}

function formatPass(pass: PassParameters): string {
  const parts: string[] = [
    `  temperature: ${pass.temperature}`,
    `  max_tokens:  ${pass.max_tokens}`,
    `  prompt_sha256: ${pass.prompt_sha256}`,
  ];
  if (pass.top_p !== undefined) {
    parts.splice(1, 0, `  top_p:       ${pass.top_p}`);
  }
  if (pass.visual_token_budget !== undefined) {
    parts.splice(parts.length - 1, 0, `  visual_token_budget: ${pass.visual_token_budget}`);
  }
  return parts.join("\n");
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
