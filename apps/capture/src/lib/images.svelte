<script lang="ts">
  import Icon from "./icons.svelte";

  type Props = {
    paths: readonly string[];
    isBusy: boolean;
    onPick: () => void;
  };

  let { paths, isBusy, onPick }: Props = $props();

  const fileNames = $derived(
    paths.map((path) => ({
      full: path,
      name: path.split(/[\\/]/).pop() ?? path
    }))
  );
</script>

<section class="card">
  <header class="card-head">
    <div class="card-title">
      <span class="icon-wrap">
        <Icon name="image" size={16} />
      </span>
      <div>
        <h2>Images</h2>
        <p>Optional. Hashed as raw bytes; never re-encoded.</p>
      </div>
    </div>
    {#if paths.length > 0}
      <span class="status-pill">
        {paths.length} {paths.length === 1 ? "image" : "images"}
      </span>
    {/if}
  </header>

  {#if paths.length === 0}
    <button class="dropzone" type="button" onclick={onPick} disabled={isBusy}>
      <div class="dropzone-icon" aria-hidden="true">
        <Icon name="image" size={22} />
      </div>
      <div class="dropzone-copy">
        <span class="dropzone-title">Add images</span>
        <span class="dropzone-sub">JPEG or PNG, original bytes preserved</span>
      </div>
    </button>
  {:else}
    <ul class="file-list">
      {#each fileNames as file (file.full)}
        <li class="file-row">
          <span class="file-icon" aria-hidden="true">
            <Icon name="image" size={14} />
          </span>
          <span class="file-name" title={file.full}>{file.name}</span>
        </li>
      {/each}
    </ul>

    <button class="secondary" type="button" onclick={onPick} disabled={isBusy}>
      Replace selection
    </button>
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
    background: rgba(124, 58, 237, 0.16);
    color: #a78bfa;
    display: grid;
    place-items: center;
    border: 1px solid rgba(124, 58, 237, 0.32);
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
    background: var(--color-bg-inset);
    border: 1px solid var(--color-border-default);
    padding: 4px 10px;
    border-radius: var(--radius-pill);
    font-size: var(--font-size-xs);
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: var(--tracking-wide);
  }

  .dropzone {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    width: 100%;
    background: var(--color-bg-inset);
    border: 1px dashed var(--color-border-default);
    border-radius: var(--radius-md);
    padding: var(--space-5);
    text-align: left;
    transition:
      background var(--transition-base),
      border-color var(--transition-base);
  }

  .dropzone:hover:not(:disabled) {
    background: var(--color-bg-surface-hover);
    border-color: var(--color-accent-border);
  }

  .dropzone:disabled {
    opacity: 0.5;
  }

  .dropzone-icon {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    background: var(--color-bg-surface);
    color: var(--color-text-secondary);
    display: grid;
    place-items: center;
    border: 1px solid var(--color-border-subtle);
  }

  .dropzone-copy {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .dropzone-title {
    font-size: var(--font-size-md);
    font-weight: 500;
    color: var(--color-text-primary);
  }

  .dropzone-sub {
    font-size: var(--font-size-sm);
    color: var(--color-text-tertiary);
  }

  .file-list {
    list-style: none;
    margin: 0 0 var(--space-4);
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
    background: var(--color-bg-inset);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-2);
    max-height: 220px;
    overflow-y: auto;
  }

  .file-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-sm);
    font-size: var(--font-size-sm);
    color: var(--color-text-secondary);
  }

  .file-row:hover {
    background: var(--color-bg-surface-hover);
    color: var(--color-text-primary);
  }

  .file-icon {
    color: var(--color-text-tertiary);
    flex-shrink: 0;
  }

  .file-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
  }

  .secondary {
    background: transparent;
    color: var(--color-text-secondary);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    padding: var(--space-2) var(--space-4);
    font-size: var(--font-size-sm);
    transition:
      background var(--transition-base),
      color var(--transition-base);
  }

  .secondary:hover:not(:disabled) {
    background: var(--color-bg-surface-hover);
    color: var(--color-text-primary);
  }

  .secondary:disabled {
    opacity: 0.5;
  }
</style>
