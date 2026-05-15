<script lang="ts">
  import Icon, { type IconName } from "./icons.svelte";

  type Props = {
    label: string;
    helper?: string;
    icon?: IconName;
    disabled?: boolean;
    busy?: boolean;
    busyLabel?: string;
    onClick: () => void;
  };

  let {
    label,
    helper,
    icon = "arrow-right",
    disabled = false,
    busy = false,
    busyLabel,
    onClick
  }: Props = $props();
</script>

<div class="action-bar">
  {#if helper !== undefined}
    <p class="helper">{helper}</p>
  {/if}
  <button
    class="primary"
    type="button"
    onclick={onClick}
    disabled={disabled || busy}
  >
    {#if busy}
      <span class="spinner" aria-hidden="true"></span>
      <span>{busyLabel ?? label}</span>
    {:else}
      <span>{label}</span>
      <Icon name={icon} size={14} />
    {/if}
  </button>
</div>

<style>
  .action-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    padding: var(--space-4) var(--space-5);
    background: var(--color-bg-surface-raised);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-md);
  }

  .helper {
    margin: 0;
    color: var(--color-text-secondary);
    font-size: var(--font-size-sm);
    line-height: var(--leading-normal);
  }

  .primary {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-5);
    background: var(--color-accent);
    color: var(--color-text-inverse);
    border-radius: var(--radius-md);
    font-weight: 600;
    font-size: var(--font-size-sm);
    letter-spacing: var(--tracking-tight);
    transition:
      background var(--transition-base),
      transform var(--transition-fast);
    flex-shrink: 0;
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.18) inset, var(--shadow-sm);
  }

  .primary:hover:not(:disabled) {
    background: var(--color-accent-hover);
  }

  .primary:active:not(:disabled) {
    transform: translateY(1px);
  }

  .primary:disabled {
    background: var(--color-bg-surface);
    color: var(--color-text-tertiary);
    box-shadow: none;
    border: 1px solid var(--color-border-subtle);
  }

  .spinner {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    border: 2px solid currentColor;
    border-right-color: transparent;
    animation: spin 0.7s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  @media (max-width: 640px) {
    .action-bar {
      flex-direction: column;
      align-items: stretch;
    }
    .primary {
      justify-content: center;
    }
  }
</style>
