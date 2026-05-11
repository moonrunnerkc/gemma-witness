<script lang="ts">
  import {
    initializeDevice,
    pickImages,
    runInference,
    sealBundle,
    startRecording,
    stopRecording,
    type InferenceSummary,
    type RecordingResult,
    type SealResult
  } from "./lib/tauri-bindings";

  let phase: "idle" | "recording" | "ready" | "running" | "reviewed" | "sealed" | "error" =
    $state("idle");
  let deviceKeyId: string | null = $state(null);
  let recording: RecordingResult | null = $state(null);
  let imagePaths: readonly string[] = $state([]);
  let summary: InferenceSummary | null = $state(null);
  let sealed: SealResult | null = $state(null);
  let errorMessage: string | null = $state(null);

  function reportError(err: unknown): void {
    phase = "error";
    errorMessage = err instanceof Error ? err.message : String(err);
  }

  async function handleInit(): Promise<void> {
    try {
      deviceKeyId = await initializeDevice();
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handleRecord(): Promise<void> {
    try {
      if (phase === "recording") {
        const result = await stopRecording();
        recording = result;
        phase = imagePaths.length > 0 ? "ready" : "idle";
        return;
      }
      await startRecording();
      phase = "recording";
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handlePickImages(): Promise<void> {
    try {
      const paths = await pickImages();
      imagePaths = paths;
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
      summary = await runInference(recording.path, imagePaths);
      phase = "reviewed";
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handleSeal(): Promise<void> {
    try {
      sealed = await sealBundle();
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
      <p><strong>narrative:</strong> {summary.narrative_summary}</p>
      <p>
        <strong>consistency:</strong>
        {summary.consistency_verdict} - {summary.consistency_reason}
      </p>
      <details>
        <summary>transcript</summary>
        <pre>{summary.transcript}</pre>
      </details>
      <details>
        <summary>structured report</summary>
        <pre>{summary.structured_report_json}</pre>
      </details>
    </section>
  {/if}

  {#if sealed !== null}
    <section class="sealed">
      <h2>sealed</h2>
      <p>bundle id: <code>{sealed.bundle_id}</code></p>
      <p>path: <code>{sealed.bundle_path}</code></p>
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
