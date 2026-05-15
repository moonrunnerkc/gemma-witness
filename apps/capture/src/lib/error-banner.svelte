<script lang="ts">
  import Icon from "./icons.svelte";

  type Props = {
    message: string;
    onDismiss: () => void;
  };

  let { message, onDismiss }: Props = $props();
</script>

<div class="error" role="alert">
  <span class="icon" aria-hidden="true">
    <Icon name="alert" size={16} />
  </span>
  <div class="body">
    <span class="title">Capture error</span>
    <p class="message">{message}</p>
  </div>
  <button class="dismiss" type="button" onclick={onDismiss}>Dismiss</button>
</div>

<style>
  .error {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-5);
    background: var(--color-danger-soft);
    border: 1px solid var(--color-danger-border);
    border-radius: var(--radius-lg);
    color: var(--color-text-primary);
  }

  .icon {
    color: var(--color-danger);
    margin-top: 2px;
    flex-shrink: 0;
  }

  .body {
    flex: 1;
    min-width: 0;
  }

  .title {
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--color-danger);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
  }

  .message {
    margin: 4px 0 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-secondary);
    line-height: var(--leading-relaxed);
    word-break: break-word;
  }

  .dismiss {
    background: transparent;
    border: 1px solid var(--color-border-default);
    color: var(--color-text-secondary);
    padding: 4px var(--space-3);
    border-radius: var(--radius-sm);
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    transition: all var(--transition-base);
    flex-shrink: 0;
  }

  .dismiss:hover {
    color: var(--color-text-primary);
    border-color: var(--color-border-strong);
  }
</style>
