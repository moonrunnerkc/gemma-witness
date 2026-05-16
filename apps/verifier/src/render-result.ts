import type {
  AmendsReference,
  AudioFingerprint,
  InferenceParameters,
  Manifest,
  PassParameters,
  SignerAttestation,
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

  if (manifest.signer.attestation) {
    container.appendChild(renderAttestationRow(manifest.signer.attestation));
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

/**
 * Render the hardware-key attestation blob carried by v2 manifests.
 *
 * The blob is informational: the verifier neither rejects nor accepts a
 * bundle on its presence under the WS3-1 spec. We surface the format tag,
 * the byte length of the payload, and a short hexadecimal preview so a
 * reviewer can compare the value against an out-of-band attestation
 * publication if they have one. The full payload is opaque under the
 * format-specific schema; truncating preserves the row layout while still
 * conveying that real bytes are present.
 */
function renderAttestationRow(att: SignerAttestation): HTMLElement {
  const row = document.createElement("div");
  row.className = "row advisory";
  row.innerHTML = `<div class="row-name">Signer attestation (${escapeHtml(att.format)})</div><div class="row-status">Advisory</div>`;
  const drill = document.createElement("div");
  drill.className = "drilldown";
  drill.textContent = summarizeAttestation(att);
  row.appendChild(drill);
  return row;
}

/**
 * Convert a [`SignerAttestation`] into the human-readable drilldown text
 * shown under the verifier's "Signer attestation" row. Extracted from the
 * DOM-bound renderer so it can be unit-tested without a browser context.
 *
 * Output shape (newline-separated):
 *   format:       <format tag>
 *   payload_size: <N bytes>
 *   payload_hex:  <first 32 bytes as space-separated hex, then "..." if longer>
 *   cert_chain:   <count or "(none)">
 *
 * A malformed payload_b64 surfaces as a non-fatal "(payload_b64 did not
 * decode as valid base64)" rather than crashing the row: the bundle's
 * signature has already verified by the time we reach this advisory.
 */
export function summarizeAttestation(att: SignerAttestation): string {
  let payloadBytes = 0;
  let preview = "";
  try {
    const bin = atob(att.payload_b64);
    payloadBytes = bin.length;
    const previewLen = Math.min(32, bin.length);
    const hex: string[] = new Array(previewLen);
    for (let i = 0; i < previewLen; i++) {
      hex[i] = bin.charCodeAt(i).toString(16).padStart(2, "0");
    }
    preview = hex.join(" ");
    if (bin.length > previewLen) {
      preview += " ... (truncated)";
    }
  } catch {
    preview = "(payload_b64 did not decode as valid base64)";
  }

  const lines: string[] = [
    `format:       ${att.format}`,
    `payload_size: ${payloadBytes} bytes`,
    `payload_hex:  ${preview}`,
  ];
  if (att.certificate_chain_b64 && att.certificate_chain_b64.length > 0) {
    lines.push(`cert_chain:   ${att.certificate_chain_b64.length} certificate(s)`);
  } else {
    lines.push(`cert_chain:   (none)`);
  }
  return lines.join("\n");
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
