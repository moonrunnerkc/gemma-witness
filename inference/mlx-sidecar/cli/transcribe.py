"""Command-line transcriber that posts a WAV to the local mlx-vlm sidecar.

Usage:
    python transcribe.py path/to/audio.wav [--endpoint ...] [--prompt ...] [--max-tokens N]

The sidecar must already be running. Start it with ../start.sh.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final

import requests

DEFAULT_ENDPOINT: Final[str] = "http://127.0.0.1:8080"
DEFAULT_PROMPT: Final[str] = "Transcribe this audio"
DEFAULT_MAX_TOKENS: Final[int] = 500
DEFAULT_MODEL: Final[str] = "mlx-community/gemma-4-e4b-it-4bit"
REQUEST_TIMEOUT_SECONDS: Final[float] = 300.0


class TranscribeError(RuntimeError):
    """Raised when the CLI cannot produce a transcript."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments for the transcribe CLI."""
    parser = argparse.ArgumentParser(
        description="Transcribe a WAV file via the local mlx-vlm sidecar.",
    )
    parser.add_argument(
        "audio",
        type=Path,
        help="Path to a WAV file readable by the sidecar process.",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default=DEFAULT_ENDPOINT,
        help=f"Sidecar base URL (default: {DEFAULT_ENDPOINT}).",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=DEFAULT_PROMPT,
        help=f"User prompt sent alongside the audio (default: {DEFAULT_PROMPT!r}).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=f"Maximum tokens to generate (default: {DEFAULT_MAX_TOKENS}).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=DEFAULT_MODEL,
        help=f"Model id to invoke on the sidecar (default: {DEFAULT_MODEL}).",
    )
    return parser.parse_args(argv)


def resolve_audio_path(path: Path) -> Path:
    """Return an absolute path the sidecar process can open, or raise."""
    if not path.exists():
        raise TranscribeError(
            f"audio file not found at {path!s}. "
            "check the path or generate the fixture before running this CLI."
        )
    if not path.is_file():
        raise TranscribeError(
            f"audio path {path!s} is not a regular file. "
            "pass the path to a WAV file, not a directory."
        )
    return path.resolve()


def build_request_body(
    *,
    model: str,
    prompt: str,
    audio_path: Path,
    max_tokens: int,
) -> dict[str, object]:
    """Build the OpenAI-compatible chat/completions body for an audio request.

    mlx-vlm's server expects ``input_audio.data`` to be a filesystem path or
    http(s) URL, not raw base64. See docs/decisions.md ("Sidecar request shape").
    """
    return {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.0,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": prompt},
                    {
                        "type": "input_audio",
                        "input_audio": {"data": str(audio_path), "format": "wav"},
                    },
                ],
            }
        ],
    }


def call_sidecar(endpoint: str, body: dict[str, object]) -> dict[str, object]:
    """POST the chat completion request and return the parsed JSON response."""
    url = endpoint.rstrip("/") + "/v1/chat/completions"
    try:
        response = requests.post(
            url,
            json=body,
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"content-type": "application/json"},
        )
    except requests.ConnectionError as exc:
        raise TranscribeError(
            f"could not connect to sidecar at {endpoint}. "
            "start the sidecar with inference/mlx-sidecar/start.sh and try again."
        ) from exc
    except requests.Timeout as exc:
        raise TranscribeError(
            f"sidecar at {endpoint} did not respond within "
            f"{REQUEST_TIMEOUT_SECONDS:.0f}s. inspect evidence/day1/sidecar.log."
        ) from exc

    if response.status_code != 200:
        raise TranscribeError(
            f"sidecar returned http {response.status_code} from {url}. "
            f"body: {response.text[:500]!r}. inspect evidence/day1/sidecar.log."
        )

    try:
        return response.json()
    except json.JSONDecodeError as exc:
        raise TranscribeError(
            f"sidecar returned non-JSON body from {url}: {response.text[:500]!r}."
        ) from exc


def extract_transcript(payload: dict[str, object]) -> str:
    """Return the assistant content from a chat-completions payload, verbatim."""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise TranscribeError(
            "sidecar response had no choices array. "
            f"payload keys: {sorted(payload.keys())!r}."
        )
    first = choices[0]
    if not isinstance(first, dict):
        raise TranscribeError("sidecar response choices[0] was not an object.")
    message = first.get("message")
    if not isinstance(message, dict):
        raise TranscribeError("sidecar response choices[0].message was not an object.")
    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise TranscribeError(
            "sidecar response choices[0].message.content was empty or not a string."
        )
    return content


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns 0 on success, non-zero on failure."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        audio_path = resolve_audio_path(args.audio)
        body = build_request_body(
            model=args.model,
            prompt=args.prompt,
            audio_path=audio_path,
            max_tokens=args.max_tokens,
        )
        payload = call_sidecar(args.endpoint, body)
        transcript = extract_transcript(payload)
    except TranscribeError as exc:
        print(f"transcribe: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(transcript)
    if not transcript.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
