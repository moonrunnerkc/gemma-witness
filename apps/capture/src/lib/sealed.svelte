<script lang="ts">
  import Icon from "./icons.svelte";
  import type { SealedBundle } from "../bindings";

  type Props = {
    sealed: SealedBundle;
    onReset: () => void;
  };

  let { sealed, onReset }: Props = $props();

  const fileName = $derived(sealed.path.split(/[\\/]/).pop() ?? sealed.path);

  let copiedField: "id" | "path" | null = $state(null);
  let copyTimer: ReturnType<typeof setTimeout> | null = null;

  async function copy(value: string, field: "id" | "path"): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      copiedField = field;
      if (copyTimer !== null) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => {
        copiedField = null;
      }, 1400);
    } catch {
      copiedField = null;
    }
  }
</script>

<section class="card">
  <div class="hero">
    <div class="hero-icon" aria-hidden="true">
      <Icon name="shield" size={24} />
    </div>
    <div>
      <h2>Bundle sealed</h2>
      <p>
        Signed with the device key and ready for verification. Share the
        <code>.witness</code> file with anyone using the static verifier.
      </p>
    </div>
  </div>

  <dl class="kv">
    <div class="kv-row">
      <dt>Bundle id</dt>
      <dd>
        <code>{sealed.bundleId}</code>
        <button
          class="copy-btn"
          type="button"
          onclick={() => copy(sealed.bundleId, "id")}
          aria-label="Copy bundle id"
        >
          {#if copiedField === "id"}
            <Icon name="check" size={12} />
            copied
          {:else}
            <Icon name="copy" size={12} />
            copy
          {/if}
        </button>
      </dd>
    </div>
    <div class="kv-row">
      <dt>File</dt>
      <dd>
        <code title={sealed.path}>{fileName}</code>
        <button
          class="copy-btn"
          type="button"
          onclick={() => copy(sealed.path, "path")}
          aria-label="Copy file path"
        >
          {#if copiedField === "path"}
            <Icon name="check" size={12} />
            copied
          {:else}
            <Icon name="copy" size={12} />
            copy path
          {/if}
        </button>
      </dd>
    </div>
  </dl>

  <div class="actions">
    <button class="primary" type="button" onclick={onReset}>
      Start a new capture
      <Icon name="arrow-right" size={14} />
    </button>
  </div>
</section>

<style>
  .card {
    background: linear-gradient(
      180deg,
      var(--color-success-soft),
      var(--color-bg-surface) 70%
    );
    border: 1px solid var(--color-success-border);
    border-radius: var(--radius-lg);
    padding: var(--space-6);
    box-shadow: var(--shadow-md);
  }

  .hero {
    display: flex;
    gap: var(--space-4);
    align-items: flex-start;
    margin-bottom: var(--space-6);
  }

  .hero-icon {
    width: 48px;
    height: 48px;
    border-radius: var(--radius-md);
    background: var(--color-success-soft);
    border: 1px solid var(--color-success-border);
    color: var(--color-success);
    display: grid;
    place-items: center;
    flex-shrink: 0;
  }

  h2 {
    margin: 0 0 var(--space-2);
    font-size: var(--font-size-xl);
    font-weight: 600;
    letter-spacing: var(--tracking-tight);
  }

  .hero p {
    margin: 0;
    color: var(--color-text-secondary);
    line-height: var(--leading-relaxed);
    font-size: var(--font-size-sm);
  }

  .hero p code {
    font-size: var(--font-size-xs);
    background: var(--color-bg-inset);
    padding: 1px 6px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-border-subtle);
    color: var(--color-text-primary);
  }

  .kv {
    margin: 0 0 var(--space-5);
    padding: 0;
    background: var(--color-bg-inset);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .kv-row {
    display: grid;
    grid-template-columns: 100px 1fr;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-4);
    align-items: center;
    border-bottom: 1px solid var(--color-border-subtle);
  }

  .kv-row:last-child {
    border-bottom: none;
  }

  dt {
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    color: var(--color-text-tertiary);
  }

  dd {
    margin: 0;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-width: 0;
  }

  dd code {
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--color-text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
    min-width: 0;
  }

  .copy-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    font-size: var(--font-size-xs);
    color: var(--color-text-tertiary);
    background: var(--color-bg-surface);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-sm);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
    transition:
      color var(--transition-base),
      border-color var(--transition-base);
    flex-shrink: 0;
  }

  .copy-btn:hover {
    color: var(--color-text-primary);
    border-color: var(--color-border-strong);
  }

  .actions {
    display: flex;
    justify-content: flex-end;
  }

  .primary {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-5);
    background: var(--color-text-primary);
    color: var(--color-text-inverse);
    border-radius: var(--radius-md);
    font-weight: 600;
    font-size: var(--font-size-sm);
    transition: background var(--transition-base);
  }

  .primary:hover {
    background: white;
  }
</style>
