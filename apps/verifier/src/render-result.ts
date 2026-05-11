import type { VerificationResult } from "./types";

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
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
