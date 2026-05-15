<script lang="ts" module>
  function prettifyJson(raw: string): string {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }

  function verdictTone(verdict: string): "ok" | "warn" | "neutral" {
    const v = verdict.trim().toLowerCase();
    if (v.startsWith("consistent")) return "ok";
    if (v.startsWith("inconsistent") || v.startsWith("conflict")) return "warn";
    return "neutral";
  }
</script>

<script lang="ts">
  import Icon from "./icons.svelte";
  import type { InferenceSummary } from "../bindings";

  type Props = { summary: InferenceSummary };
  let { summary }: Props = $props();

  const tone = $derived(verdictTone(summary.consistencyVerdict));
  const prettyReport = $derived(prettifyJson(summary.structuredReportJson));
  const latencyLabel = $derived(
    summary.totalLatencyMs >= 1000
      ? `${(summary.totalLatencyMs / 1000).toFixed(2)} s`
      : `${summary.totalLatencyMs} ms`
  );
</script>

<section class="card">
  <header class="card-head">
    <div class="card-title">
      <span class="icon-wrap">
        <Icon name="sparkles" size={16} />
      </span>
      <div>
        <h2>Inference review</h2>
        <p>Verify the model output before sealing. Reasoning is captured verbatim.</p>
      </div>
    </div>
    <span class="latency">
      <Icon name="circle" size={6} />
      {latencyLabel}
    </span>
  </header>

  <div class="grid">
    <article class="block block--narrative">
      <div class="block-label">Narrative</div>
      <p class="narrative">{summary.narrativeSummary}</p>
    </article>

    <article class="block block--verdict" data-tone={tone}>
      <div class="block-label">Consistency verdict</div>
      <div class="verdict-line">
        <span class="verdict-tag">{summary.consistencyVerdict}</span>
      </div>
      <p class="verdict-reason">{summary.consistencyReason}</p>
    </article>
  </div>

  {#if summary.imageDescriptions.length > 0}
    <article class="block">
      <div class="block-label">Image descriptions</div>
      <ol class="image-list">
        {#each summary.imageDescriptions as desc, i (i)}
          <li>
            <span class="image-num">{i + 1}</span>
            <span>{desc}</span>
          </li>
        {/each}
      </ol>
    </article>
  {/if}

  <details class="disclosure">
    <summary>
      <Icon name="arrow-right" size={12} />
      Transcript
      <span class="disclosure-meta">{summary.transcript.length.toLocaleString()} chars</span>
    </summary>
    <pre>{summary.transcript}</pre>
  </details>

  <details class="disclosure">
    <summary>
      <Icon name="arrow-right" size={12} />
      Structured report
      <span class="disclosure-meta">JSON</span>
    </summary>
    <pre>{prettyReport}</pre>
  </details>

  <div class="trace-row">
    <span class="trace-label">Reasoning trace</span>
    <code class="trace-path" title={summary.reasoningTracePath}>
      {summary.reasoningTracePath}
    </code>
  </div>
</section>

<style>
  .card {
    background: var(--color-bg-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-lg);
    padding: var(--space-6);
    box-shadow: var(--shadow-sm);
  }

  .card-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
    margin-bottom: var(--space-5);
  }

  .card-title {
    display: flex;
    gap: var(--space-3);
    align-items: flex-start;
  }

  .icon-wrap {
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background: rgba(245, 158, 11, 0.14);
    color: #fbbf24;
    display: grid;
    place-items: center;
    border: 1px solid rgba(245, 158, 11, 0.32);
    flex-shrink: 0;
  }

  h2 {
    margin: 0;
    font-size: var(--font-size-md);
    font-weight: 600;
    letter-spacing: var(--tracking-tight);
  }

  .card-title p {
    margin: 2px 0 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-tertiary);
  }

  .latency {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--color-text-tertiary);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
  }

  .grid {
    display: grid;
    grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr);
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }

  @media (max-width: 760px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }

  .block {
    background: var(--color-bg-inset);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-bottom: var(--space-3);
  }

  .block-label {
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    color: var(--color-text-tertiary);
    margin-bottom: var(--space-2);
  }

  .narrative {
    margin: 0;
    font-size: var(--font-size-md);
    line-height: var(--leading-relaxed);
    color: var(--color-text-primary);
  }

  .block--verdict[data-tone="ok"] {
    border-color: var(--color-success-border);
    background: linear-gradient(
      180deg,
      var(--color-success-soft),
      var(--color-bg-inset)
    );
  }

  .block--verdict[data-tone="warn"] {
    border-color: var(--color-warning-soft);
    background: linear-gradient(
      180deg,
      var(--color-warning-soft),
      var(--color-bg-inset)
    );
  }

  .verdict-tag {
    display: inline-block;
    font-size: var(--font-size-sm);
    font-weight: 600;
    letter-spacing: var(--tracking-tight);
    color: var(--color-text-primary);
    text-transform: capitalize;
  }

  .verdict-reason {
    margin: var(--space-2) 0 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-secondary);
    line-height: var(--leading-relaxed);
  }

  .image-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .image-list li {
    display: flex;
    gap: var(--space-3);
    font-size: var(--font-size-sm);
    color: var(--color-text-secondary);
    line-height: var(--leading-relaxed);
  }

  .image-num {
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--color-text-tertiary);
    min-width: 16px;
  }

  .disclosure {
    background: var(--color-bg-inset);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-3);
    overflow: hidden;
  }

  .disclosure summary {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    cursor: pointer;
    list-style: none;
    color: var(--color-text-secondary);
    font-size: var(--font-size-sm);
    font-weight: 500;
    transition:
      background var(--transition-base),
      color var(--transition-base);
  }

  .disclosure summary::-webkit-details-marker {
    display: none;
  }

  .disclosure summary:hover {
    background: var(--color-bg-surface-hover);
    color: var(--color-text-primary);
  }

  .disclosure[open] summary {
    border-bottom: 1px solid var(--color-border-subtle);
  }

  .disclosure summary :global(svg) {
    transition: transform var(--transition-base);
    color: var(--color-text-tertiary);
  }

  .disclosure[open] summary :global(svg) {
    transform: rotate(90deg);
  }

  .disclosure-meta {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--color-text-tertiary);
    letter-spacing: var(--tracking-wide);
    text-transform: uppercase;
  }

  pre {
    margin: 0;
    padding: var(--space-4);
    font-size: var(--font-size-xs);
    color: var(--color-text-secondary);
    line-height: var(--leading-relaxed);
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 320px;
    overflow-y: auto;
  }

  .trace-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--color-border-subtle);
    font-size: var(--font-size-xs);
    color: var(--color-text-tertiary);
  }

  .trace-label {
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
  }

  .trace-path {
    font-family: var(--font-mono);
    color: var(--color-text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
    min-width: 0;
  }
</style>
