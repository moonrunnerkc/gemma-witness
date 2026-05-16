import type { AppError } from "../bindings";

/**
 * Wire shape of every command in {@link bindings.commands}. tauri-specta
 * generates each call site as `typedError<T, AppError>(__TAURI_INVOKE(...))`,
 * which returns this envelope so callers can branch on the discriminant
 * without a thrown exception crossing the IPC boundary.
 */
export type Envelope<T> =
  | { status: "ok"; data: T }
  | { status: "error"; error: AppError };

/**
 * Await a tauri-specta command envelope and either return its payload or
 * throw a JavaScript `Error` carrying the typed `AppError`. Use this at every
 * call site instead of branching on `result.status` manually so that callers
 * can rely on the conventional throw-on-failure shape.
 *
 * The thrown `Error` exposes the original `AppError` on `cause` for callers
 * that want to render typed-variant detail (the message is a flat string for
 * generic error-boundary rendering).
 *
 * @param promise A `Promise` returned by any `commands.*` call.
 * @returns The unwrapped success payload of type `T`.
 * @throws `Error` with `cause` set to the `AppError` when the command failed.
 */
export async function unwrap<T>(promise: Promise<Envelope<T>>): Promise<T> {
  const result = await promise;
  if (result.status === "error") {
    const message =
      typeof result.error === "string"
        ? result.error
        : JSON.stringify(result.error);
    throw new Error(message, { cause: result.error });
  }
  return result.data;
}
