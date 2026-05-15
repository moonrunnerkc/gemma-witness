<script lang="ts" module>
  export type StepKey = "capture" | "inference" | "review" | "seal";

  export type Step = {
    key: StepKey;
    label: string;
    description: string;
  };

  export const STEPS: readonly Step[] = [
    { key: "capture", label: "Capture", description: "Audio and images" },
    { key: "inference", label: "Inference", description: "Run Gemma locally" },
    { key: "review", label: "Review", description: "Verify the report" },
    { key: "seal", label: "Seal", description: "Sign the bundle" }
  ];
</script>

<script lang="ts">
  import Icon from "./icons.svelte";

  type Props = { current: StepKey; completed: ReadonlySet<StepKey> };
  let { current, completed }: Props = $props();

  const indexOf = (key: StepKey): number =>
    STEPS.findIndex((step) => step.key === key);

  const status = (key: StepKey): "done" | "active" | "pending" => {
    if (completed.has(key)) return "done";
    if (key === current) return "active";
    return "pending";
  };

  const currentIndex = $derived(indexOf(current));
</script>

<ol class="stepper" aria-label="Capture workflow progress">
  {#each STEPS as step, i (step.key)}
    {@const state = status(step.key)}
    <li class="step" data-state={state}>
      <div class="marker" aria-hidden="true">
        {#if state === "done"}
          <Icon name="check" size={14} />
        {:else}
          <span class="marker-num">{i + 1}</span>
        {/if}
      </div>
      <div class="meta">
        <span class="label">{step.label}</span>
        <span class="description">{step.description}</span>
      </div>
      {#if i < STEPS.length - 1}
        <div
          class="connector"
          data-filled={i < currentIndex || completed.has(step.key)}
          aria-hidden="true"
        ></div>
      {/if}
    </li>
  {/each}
</ol>

<style>
  .stepper {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0;
    background: var(--color-bg-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-lg);
    padding: var(--space-5) var(--space-5);
    box-shadow: var(--shadow-sm);
  }

  .step {
    position: relative;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-width: 0;
  }

  .marker {
    width: 28px;
    height: 28px;
    border-radius: var(--radius-pill);
    display: grid;
    place-items: center;
    background: var(--color-bg-inset);
    border: 1px solid var(--color-border-default);
    color: var(--color-text-tertiary);
    flex-shrink: 0;
    transition:
      background var(--transition-base),
      border-color var(--transition-base),
      color var(--transition-base);
  }

  .marker-num {
    font-size: var(--font-size-xs);
    font-weight: 600;
    letter-spacing: var(--tracking-wide);
  }

  .step[data-state="active"] .marker {
    background: var(--color-accent-muted);
    border-color: var(--color-accent-border);
    color: var(--color-accent);
    box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.10);
  }

  .step[data-state="done"] .marker {
    background: var(--color-success-soft);
    border-color: var(--color-success-border);
    color: var(--color-success);
  }

  .meta {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .label {
    font-size: var(--font-size-sm);
    font-weight: 600;
    letter-spacing: var(--tracking-tight);
    color: var(--color-text-secondary);
    transition: color var(--transition-base);
  }

  .step[data-state="active"] .label {
    color: var(--color-text-primary);
  }

  .step[data-state="done"] .label {
    color: var(--color-text-primary);
  }

  .description {
    font-size: var(--font-size-xs);
    color: var(--color-text-tertiary);
    letter-spacing: var(--tracking-wide);
    text-transform: uppercase;
    margin-top: 2px;
  }

  .connector {
    position: absolute;
    top: 14px;
    left: calc(28px + var(--space-3));
    right: var(--space-2);
    height: 1px;
    background: var(--color-border-subtle);
    transform: translateX(var(--space-3));
  }

  .connector[data-filled="true"] {
    background: linear-gradient(
      to right,
      var(--color-success-border),
      var(--color-accent-border)
    );
  }

  @media (max-width: 720px) {
    .stepper {
      grid-template-columns: 1fr;
      gap: var(--space-3);
    }
    .connector {
      display: none;
    }
    .description {
      display: none;
    }
  }
</style>
