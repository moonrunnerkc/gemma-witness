/**
 * Typed wrappers around Tauri commands exposed by the Rust backend.
 *
 * Hand-written to keep the surface small. Every exported helper matches
 * one `#[tauri::command]` in `src-tauri/src/commands/`. Keep this file in
 * lockstep with the Rust side: a stale binding here is a runtime crash,
 * not a compile error.
 */

import { invoke } from "@tauri-apps/api/core";

/** Outcome of a successful audio recording. */
export interface RecordingResult {
  readonly path: string;
  readonly duration_ms: number;
  readonly sample_rate_hz: number;
  readonly channels: number;
}

/** Outcome of a sealed bundle. */
export interface SealResult {
  readonly bundle_path: string;
  readonly bundle_id: string;
}

/** Inference pipeline summary for the UI review step. */
export interface InferenceSummary {
  readonly transcript: string;
  readonly narrative_summary: string;
  readonly consistency_verdict: string;
  readonly consistency_reason: string;
  readonly latency_ms: number;
  readonly reasoning_trace_path: string;
  readonly structured_report_json: string;
}

/**
 * Begin recording. Resolves once the underlying device opens.
 *
 * @returns absolute path the WAV will be written to on stop
 * @throws if the system has no input device or the user denied access
 */
export const startRecording = (): Promise<string> => invoke<string>("start_recording");

/**
 * Stop the in-flight recording and flush WAV bytes to disk.
 *
 * @returns metadata about the produced WAV file
 * @throws if no recording is currently active
 */
export const stopRecording = (): Promise<RecordingResult> =>
  invoke<RecordingResult>("stop_recording");

/**
 * Open the native file picker, restricted to image extensions.
 *
 * @returns list of selected file paths, capped at 4
 * @throws on validation failures (too many files, oversized, wrong extension)
 */
export const pickImages = (): Promise<readonly string[]> =>
  invoke<readonly string[]>("pick_images");

/**
 * Drive the four-pass Gemma inference pipeline.
 *
 * @param audioPath absolute path to a WAV produced by stopRecording
 * @param imagePaths absolute paths returned by pickImages
 * @returns summary for the human-review UI
 * @throws if the sidecar at http://localhost:8080 is unreachable
 */
export const runInference = (
  audioPath: string,
  imagePaths: readonly string[]
): Promise<InferenceSummary> =>
  invoke<InferenceSummary>("run_inference", { audioPath, imagePaths });

/**
 * Seal a `.witness` bundle from the in-flight capture state.
 *
 * @returns the absolute path of the produced bundle and its UUID
 * @throws if any asset is missing or the keychain rejects signing
 */
export const sealBundle = (): Promise<SealResult> => invoke<SealResult>("seal_bundle");

/** Initialize device key on first launch. Returns the public-key id. */
export const initializeDevice = (): Promise<string> => invoke<string>("initialize_device");
