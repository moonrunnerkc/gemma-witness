<script lang="ts">
  import Icon from "./icons.svelte";

  type Props = { deviceKeyId: string | null };
  let { deviceKeyId }: Props = $props();

  const shortKey = $derived(
    deviceKeyId === null
      ? null
      : `${deviceKeyId.slice(0, 8)} · ${deviceKeyId.slice(-6)}`
  );

  let copied = $state(false);
  let copyTimer: ReturnType<typeof setTimeout> | null = null;

  async function copyKey(): Promise<void> {
    if (deviceKeyId === null) return;
    try {
      await navigator.clipboard.writeText(deviceKeyId);
      copied = true;
      if (copyTimer !== null) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => {
        copied = false;
      }, 1400);
    } catch {
      copied = false;
    }
  }
</script>

<header class="header">
  <div class="brand">
    <div class="brand-mark" aria-hidden="true">
      <Icon name="shield" size={18} />
    </div>
    <div class="brand-text">
      <span class="title">Gemma<span class="dot">.</span>Witness</span>
      <span class="tagline">Tamper-evident evidence capture</span>
    </div>
  </div>

  <div class="meta">
    {#if deviceKeyId !== null && shortKey !== null}
      <button
        class="device-chip"
        type="button"
        onclick={copyKey}
        title="Click to copy full device key id"
      >
        <Icon name="key" size={12} />
        <span class="device-label">Device</span>
        <code class="device-key">{shortKey}</code>
        <span class="device-action" aria-live="polite">
          {#if copied}
            <Icon name="check" size={12} />
            copied
          {:else}
            <Icon name="copy" size={12} />
          {/if}
        </span>
      </button>
    {:else}
      <div class="device-chip device-chip--loading" aria-live="polite">
        <span class="pulse"></span>
        <span class="device-label">Initializing device key</span>
      </div>
    {/if}
  </div>
</header>

<style>
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-6);
    padding: var(--space-5) 0;
    border-bottom: 1px solid var(--color-border-subtle);
    flex-wrap: wrap;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .brand-mark {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-md);
    background: linear-gradient(
      135deg,
      var(--color-accent-muted),
      rgba(124, 58, 237, 0.18)
    );
    border: 1px solid var(--color-accent-border);
    color: var(--color-accent);
    display: grid;
    place-items: center;
  }

  .brand-text {
    display: flex;
    flex-direction: column;
    line-height: 1.1;
  }

  .title {
    font-size: var(--font-size-lg);
    font-weight: 600;
    letter-spacing: var(--tracking-tight);
    color: var(--color-text-primary);
  }

  .dot {
    color: var(--color-accent);
  }

  .tagline {
    font-size: var(--font-size-xs);
    color: var(--color-text-tertiary);
    letter-spacing: var(--tracking-wide);
    text-transform: uppercase;
    margin-top: 4px;
  }

  .meta {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .device-chip {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: 6px var(--space-3);
    background: var(--color-bg-surface);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-pill);
    color: var(--color-text-secondary);
    font-size: var(--font-size-xs);
    letter-spacing: var(--tracking-wide);
    transition:
      background var(--transition-base),
      border-color var(--transition-base);
  }

  .device-chip:hover:not(:disabled):not(.device-chip--loading) {
    background: var(--color-bg-surface-hover);
    border-color: var(--color-border-strong);
    color: var(--color-text-primary);
  }

  .device-label {
    text-transform: uppercase;
    color: var(--color-text-tertiary);
  }

  .device-key {
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--color-text-primary);
    letter-spacing: 0;
  }

  .device-action {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--color-text-tertiary);
  }

  .pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-warning);
    box-shadow: 0 0 0 0 var(--color-warning);
    animation: pulse 1.6s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 0.6;
      transform: scale(0.85);
    }
    50% {
      opacity: 1;
      transform: scale(1);
    }
  }
</style>
