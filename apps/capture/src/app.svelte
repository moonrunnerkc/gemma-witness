<script lang="ts">
  import {
    commands,
    type RecordingFinished,
    type InferenceSummary,
    type SealedBundle
  } from "./bindings";

  let phase: "idle" | "recording" | "ready" | "running" | "reviewed" | "sealed" | "error" =
    $state("idle");
  let deviceKeyId: string | null = $state(null);
  let recording: RecordingFinished | null = $state(null);
  let imagePaths: readonly string[] = $state([]);
  let summary: InferenceSummary | null = $state(null);
  let sealed: SealedBundle | null = $state(null);
  let errorMessage: string | null = $state(null);

  function reportError(err: unknown): void {
    phase = "error";
    errorMessage = err instanceof Error ? err.message : String(err);
  }

  async function handleInit(): Promise<void> {
    try {
      deviceKeyId = await commands.initialize_device();
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handleRecord(): Promise<void> {
    try {
      if (phase === "recording") {
        const result = await commands.stop_recording_cmd();
        recording = result;
        phase = imagePaths.length > 0 ? "ready" : "idle";
        return;
      }
      await commands.start_recording_cmd();
      phase = "recording";
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handlePickImages(): Promise<void> {
    try {
      const picked = await commands.pick_images_cmd();
      imagePaths = picked.paths;
      if (recording !== null) {
        phase = "ready";
      }
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handleRunInference(): Promise<void> {
    if (recording === null) {
      return;
    }
    phase = "running";
    try {
      summary = await commands.run_inference_cmd();
      phase = "reviewed";
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handleSeal(): Promise<void> {
    try {
      sealed = await commands.seal_bundle_cmd();
      phase = "sealed";
    } catch (err: unknown) {
      reportError(err);
    }
  }

  void handleInit();
</script>

<main>
  <h1>Gemma.Witness capture</h1>

  {#if deviceKeyId !== null}
    <p class="device">device key: <code>{deviceKeyId.slice(0, 16)}…</code></p>
  {/if}

  <section>
    <button onclick={handleRecord} disabled={phase === "running"}>
      {phase === "recording" ? "stop recording" : "record audio"}
    </button>
    <button onclick={handlePickImages} disabled={phase === "recording" || phase === "running"}>
      pick images ({imagePaths.length})
    </button>
    <button
      onclick={handleRunInference}
      disabled={recording === null || phase === "running"}
    >
      run inference
    </button>
    <button
      onclick={handleSeal}
      disabled={summary === null || phase !== "reviewed"}
    >
      seal bundle
    </button>
  </section>

  {#if summary !== null}
    <section class="summary">
      <h2>review</h2>
      <p><strong>narrative:</strong> {summary.narrativeSummary}</p>
      <p>
        <strong>consistency:</strong>
        {summary.consistencyVerdict} - {summary.consistencyReason}
      </p>
      <details>
        <summary>transcript</summary>
        <pre>{summary.transcript}</pre>
      </details>
      <details>
        <summary>structured report</summary>
        <pre>{summary.structuredReportJson}</pre>
      </details>
    </section>
  {/if}

  {#if sealed !== null}
    <section class="sealed">
      <h2>sealed</h2>
      <p>bundle id: <code>{sealed.bundleId}</code></p>
      <p>path: <code>{sealed.path}</code></p>
    </section>
  {/if}

  {#if errorMessage !== null}
    <section class="error"><strong>error:</strong> {errorMessage}</section>
  {/if}
</main>

<style>
  main {
    font-family: -apple-system, system-ui, sans-serif;
    max-width: 760px;
    margin: 2rem auto;
    padding: 0 1rem;
  }
  button {
    margin: 0.25rem 0.5rem 0.25rem 0;
    padding: 0.5rem 0.75rem;
  }
  pre {
    background: #f4f4f4;
    padding: 0.5rem;
    overflow-x: auto;
    white-space: pre-wrap;
  }
  .error {
    color: #b00020;
  }
</style>
