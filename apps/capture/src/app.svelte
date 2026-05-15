<script lang="ts">
  import {
    commands,
    type AppError,
    type RecordingFinished,
    type InferenceSummary,
    type SealedBundle
  } from "./bindings";
  import Header from "./lib/header.svelte";
  import Stepper, { type StepKey } from "./lib/stepper.svelte";
  import Recorder from "./lib/recorder.svelte";
  import Images from "./lib/images.svelte";
  import Review from "./lib/review.svelte";
  import Sealed from "./lib/sealed.svelte";
  import ActionBar from "./lib/action-bar.svelte";
  import ErrorBanner from "./lib/error-banner.svelte";

  type Envelope<T> = { status: "ok"; data: T } | { status: "error"; error: AppError };
  type Phase = "idle" | "recording" | "ready" | "running" | "reviewed" | "sealed";

  async function unwrap<T>(promise: Promise<Envelope<T>>): Promise<T> {
    const result = await promise;
    if (result.status === "error") {
      throw new Error(
        typeof result.error === "string"
          ? result.error
          : JSON.stringify(result.error)
      );
    }
    return result.data;
  }

  let phase = $state<Phase>("idle");
  let deviceKeyId = $state<string | null>(null);
  let recording = $state<RecordingFinished | null>(null);
  let imagePaths = $state<readonly string[]>([]);
  let summary = $state<InferenceSummary | null>(null);
  let sealed = $state<SealedBundle | null>(null);
  let errorMessage = $state<string | null>(null);

  let recordStartedAt = $state<number | null>(null);
  let elapsedMs = $state(0);
  let timerId: ReturnType<typeof setInterval> | null = null;

  function startTimer(): void {
    recordStartedAt = Date.now();
    elapsedMs = 0;
    timerId = setInterval(() => {
      if (recordStartedAt !== null) {
        elapsedMs = Date.now() - recordStartedAt;
      }
    }, 250);
  }

  function stopTimer(): void {
    if (timerId !== null) {
      clearInterval(timerId);
      timerId = null;
    }
    recordStartedAt = null;
  }

  function reportError(err: unknown): void {
    stopTimer();
    errorMessage = err instanceof Error ? err.message : String(err);
  }

  async function handleInit(): Promise<void> {
    try {
      deviceKeyId = await unwrap(commands.initializeDevice());
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handleRecord(): Promise<void> {
    try {
      if (phase === "recording") {
        const result = await unwrap(commands.stopRecordingCmd());
        recording = result;
        stopTimer();
        phase = "ready";
        return;
      }
      await unwrap(commands.startRecordingCmd());
      startTimer();
      phase = "recording";
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handlePickImages(): Promise<void> {
    try {
      const picked = await unwrap(commands.pickImagesCmd());
      imagePaths = picked.paths;
    } catch (err: unknown) {
      reportError(err);
    }
  }

  async function handleRunInference(): Promise<void> {
    if (recording === null) return;
    phase = "running";
    try {
      summary = await unwrap(commands.runInferenceCmd());
      phase = "reviewed";
    } catch (err: unknown) {
      reportError(err);
      phase = "ready";
    }
  }

  async function handleSeal(): Promise<void> {
    try {
      sealed = await unwrap(commands.sealBundleCmd());
      phase = "sealed";
    } catch (err: unknown) {
      reportError(err);
    }
  }

  function handleReset(): void {
    phase = "idle";
    recording = null;
    imagePaths = [];
    summary = null;
    sealed = null;
    errorMessage = null;
    elapsedMs = 0;
  }

  const currentStep = $derived<StepKey>(
    phase === "running"
      ? "inference"
      : phase === "reviewed"
        ? "review"
        : phase === "sealed"
          ? "seal"
          : "capture"
  );

  const completedSteps = $derived<ReadonlySet<StepKey>>(
    new Set<StepKey>(
      phase === "sealed"
        ? ["capture", "inference", "review", "seal"]
        : phase === "reviewed"
          ? ["capture", "inference"]
          : phase === "ready" || phase === "running"
            ? phase === "ready"
              ? ["capture"]
              : ["capture"]
            : []
    )
  );

  const canRunInference = $derived(recording !== null && phase === "ready");
  const isCaptureBusy = $derived(phase === "running");

  void handleInit();
</script>

<div class="shell">
  <div class="container">
    <Header {deviceKeyId} />

    <div class="stepper-wrap">
      <Stepper current={currentStep} completed={completedSteps} />
    </div>

    {#if errorMessage !== null}
      <div class="banner-wrap">
        <ErrorBanner
          message={errorMessage}
          onDismiss={() => (errorMessage = null)}
        />
      </div>
    {/if}

    <main class="content">
      {#if phase === "sealed" && sealed !== null}
        <Sealed {sealed} onReset={handleReset} />
      {:else if phase === "reviewed" && summary !== null}
        <Review {summary} />
        <ActionBar
          label="Seal bundle"
          icon="shield"
          helper="Signs the canonicalized manifest with your device key. Bundle is written as a single .witness file."
          onClick={handleSeal}
        />
      {:else}
        <div class="capture-grid">
          <Recorder
            isRecording={phase === "recording"}
            isBusy={isCaptureBusy}
            {elapsedMs}
            {recording}
            onToggle={handleRecord}
          />
          <Images
            paths={imagePaths}
            isBusy={phase === "recording" || isCaptureBusy}
            onPick={handlePickImages}
          />
        </div>

        <ActionBar
          label="Run inference"
          icon="sparkles"
          helper={canRunInference
            ? "Sends audio and images to the local Gemma sidecar. Reasoning trace is captured verbatim."
            : "Record audio first. Images are optional."}
          disabled={!canRunInference}
          busy={phase === "running"}
          busyLabel="Running locally"
          onClick={handleRunInference}
        />
      {/if}
    </main>

    <footer class="footer">
      <span>Offline · all processing happens on this device</span>
      <span class="footer-mono">v0.1.0</span>
    </footer>
  </div>
</div>

<style>
  .shell {
    flex: 1;
    display: flex;
    justify-content: center;
    padding: var(--space-6) var(--space-5) var(--space-10);
  }

  .container {
    width: 100%;
    max-width: var(--content-max);
    display: flex;
    flex-direction: column;
  }

  .stepper-wrap {
    margin-top: var(--space-6);
  }

  .banner-wrap {
    margin-top: var(--space-5);
  }

  .content {
    margin-top: var(--space-6);
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .capture-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-5);
  }

  @media (max-width: 760px) {
    .capture-grid {
      grid-template-columns: 1fr;
    }
  }

  .footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-6) 0 var(--space-2);
    margin-top: var(--space-8);
    border-top: 1px solid var(--color-border-subtle);
    color: var(--color-text-tertiary);
    font-size: var(--font-size-xs);
    letter-spacing: var(--tracking-wide);
    text-transform: uppercase;
  }

  .footer-mono {
    font-family: var(--font-mono);
    text-transform: none;
    letter-spacing: 0;
  }
</style>
