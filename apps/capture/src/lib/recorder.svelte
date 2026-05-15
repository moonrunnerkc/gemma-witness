<script lang="ts" module>
  function pad2(n: number): string {
    return n < 10 ? `0${n}` : `${n}`;
  }

  export function formatDuration(ms: number): string {
    const totalSeconds = Math.max(0, Math.floor(ms / 1000));
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${pad2(minutes)}:${pad2(seconds)}`;
  }
</script>

<script lang="ts">
  import Icon from "./icons.svelte";
  import type { RecordingFinished } from "../bindings";

  type Props = {
    isRecording: boolean;
    isBusy: boolean;
    elapsedMs: number;
    recording: RecordingFinished | null;
    onToggle: () => void;
  };

  let { isRecording, isBusy, elapsedMs, recording, onToggle }: Props = $props();

  const durationLabel = $derived(
    isRecording
      ? formatDuration(elapsedMs)
      : recording !== null
        ? formatDuration(recording.durationMs)
        : "00:00"
  );

  const fileName = $derived(
    recording === null
      ? null
      : recording.path.split(/[\\/]/).pop() ?? recording.path
  );
</script>

<section class="card">
  <header class="card-head">
    <div class="card-title">
      <span class="icon-wrap">
        <Icon name="mic" size={16} />
      </span>
      <div>
        <h2>Audio</h2>
        <p>One continuous take. Saved as 16-bit PCM WAV.</p>
      </div>
    </div>

    {#if recording !== null && !isRecording}
      <span class="status-pill status-pill--ok">
        <Icon name="check" size={12} />
        recorded
      </span>
    {:else if isRecording}
      <span class="status-pill status-pill--live">
        <span class="live-dot" aria-hidden="true"></span>
        live
      </span>
    {/if}
  </header>

  <div class="recorder">
    <button
      class="record-btn"
      type="button"
      data-recording={isRecording}
      onclick={onToggle}
      disabled={isBusy}
      aria-pressed={isRecording}
    >
      <span class="record-glyph" aria-hidden="true">
        {#if isRecording}
          <Icon name="stop" size={20} />
        {:else}
          <Icon name="mic" size={22} />
        {/if}
      </span>
      <span class="record-label">
        {isRecording ? "Stop recording" : recording !== null ? "Re-record" : "Start recording"}
      </span>
    </button>

    <div class="display" data-recording={isRecording}>
      <div class="time" aria-live="polite">{durationLabel}</div>
      <div class="time-label">duration</div>
      {#if isRecording}
        <div class="bars" aria-hidden="true">
          <span></span><span></span><span></span><span></span><span></span>
          <span></span><span></span><span></span><span></span><span></span>
        </div>
      {/if}
    </div>
  </div>

  {#if recording !== null}
    <div class="meta-row">
      <div class="meta-item">
        <span class="meta-label">file</span>
        <code class="meta-value" title={recording.path}>{fileName}</code>
      </div>
      <div class="meta-item">
        <span class="meta-label">sample rate</span>
        <span class="meta-value">{recording.sampleRateHz.toLocaleString()} Hz</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">channels</span>
        <span class="meta-value">{recording.channels === 1 ? "mono" : `${recording.channels} ch`}</span>
      </div>
    </div>
  {/if}
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
    background: var(--color-accent-muted);
    color: var(--color-accent);
    display: grid;
    place-items: center;
    border: 1px solid var(--color-accent-border);
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

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: var(--radius-pill);
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    font-weight: 600;
    border: 1px solid transparent;
  }

  .status-pill--ok {
    background: var(--color-success-soft);
    color: var(--color-success);
    border-color: var(--color-success-border);
  }

  .status-pill--live {
    background: var(--color-record-soft);
    color: var(--color-record);
    border-color: var(--color-record-border);
  }

  .live-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-record);
    box-shadow: 0 0 0 0 currentColor;
    animation: blink 1.4s ease-in-out infinite;
  }

  @keyframes blink {
    0%, 100% { opacity: 0.4; }
    50% { opacity: 1; }
  }

  .recorder {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: var(--space-5);
    align-items: stretch;
    background: var(--color-bg-inset);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-5);
  }

  .record-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-6);
    background: var(--color-accent);
    color: var(--color-text-inverse);
    border-radius: var(--radius-md);
    font-weight: 600;
    font-size: var(--font-size-md);
    letter-spacing: var(--tracking-tight);
    transition:
      background var(--transition-base),
      transform var(--transition-fast),
      box-shadow var(--transition-base);
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.15) inset, var(--shadow-sm);
  }

  .record-btn:hover:not(:disabled) {
    background: var(--color-accent-hover);
  }

  .record-btn:active:not(:disabled) {
    transform: translateY(1px);
  }

  .record-btn:disabled {
    opacity: 0.5;
  }

  .record-btn[data-recording="true"] {
    background: var(--color-record);
    color: white;
    box-shadow:
      0 1px 0 rgba(255, 255, 255, 0.20) inset,
      0 0 0 6px var(--color-record-soft);
  }

  .record-btn[data-recording="true"]:hover:not(:disabled) {
    background: #f87171;
  }

  .record-glyph {
    display: inline-flex;
  }

  .display {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    justify-content: center;
    min-width: 140px;
    padding-left: var(--space-5);
    border-left: 1px solid var(--color-border-subtle);
  }

  .time {
    font-family: var(--font-mono);
    font-size: var(--font-size-2xl);
    font-weight: 500;
    color: var(--color-text-primary);
    font-variant-numeric: tabular-nums;
    letter-spacing: var(--tracking-tight);
    line-height: 1;
  }

  .display[data-recording="true"] .time {
    color: var(--color-record);
  }

  .time-label {
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    color: var(--color-text-tertiary);
    margin-top: 4px;
  }

  .bars {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 16px;
    margin-top: var(--space-3);
  }

  .bars span {
    width: 2px;
    background: var(--color-record);
    border-radius: 1px;
    animation: equalize 1.1s ease-in-out infinite;
  }

  .bars span:nth-child(1) { animation-delay: 0.0s; height: 30%; }
  .bars span:nth-child(2) { animation-delay: 0.1s; height: 60%; }
  .bars span:nth-child(3) { animation-delay: 0.2s; height: 90%; }
  .bars span:nth-child(4) { animation-delay: 0.3s; height: 50%; }
  .bars span:nth-child(5) { animation-delay: 0.4s; height: 80%; }
  .bars span:nth-child(6) { animation-delay: 0.5s; height: 40%; }
  .bars span:nth-child(7) { animation-delay: 0.6s; height: 70%; }
  .bars span:nth-child(8) { animation-delay: 0.7s; height: 55%; }
  .bars span:nth-child(9) { animation-delay: 0.8s; height: 85%; }
  .bars span:nth-child(10) { animation-delay: 0.9s; height: 35%; }

  @keyframes equalize {
    0%, 100% { transform: scaleY(0.4); }
    50% { transform: scaleY(1); }
  }

  .meta-row {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-6);
    margin-top: var(--space-5);
    padding-top: var(--space-4);
    border-top: 1px solid var(--color-border-subtle);
  }

  .meta-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .meta-label {
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    color: var(--color-text-tertiary);
  }

  .meta-value {
    font-size: var(--font-size-sm);
    color: var(--color-text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 320px;
  }

  @media (max-width: 640px) {
    .recorder {
      grid-template-columns: 1fr;
    }
    .display {
      align-items: flex-start;
      padding-left: 0;
      border-left: none;
      border-top: 1px solid var(--color-border-subtle);
      padding-top: var(--space-4);
    }
  }
</style>
