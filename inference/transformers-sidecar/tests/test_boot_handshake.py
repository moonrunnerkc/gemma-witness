"""Boot + handshake gate for the transformers sidecar.

These tests are the per-PR Linux gate: they confirm the FastAPI surface
boots, that `start.py` imports without raising, and that `/v1/models`
returns the OpenAI-compatible envelope a witness-inference client expects.
They do NOT load the model weights, so they run in seconds without HF
authentication and without GPU access. Full inference is validated in the
live-e2e workflow on hardware that can host the gated `google/gemma-4-E4B-it`
weights.

What this catches:
- pyproject.toml updates that break Python imports (transformers / torch /
  torchaudio / FastAPI ABI drift).
- start.py syntax errors and missing-name errors at import time.
- `/v1/models` shape regressions that would silently break the
  witness-inference HTTP client.

What this does not catch (by design):
- Model output regressions. Tested in live-e2e.
- Audio waveform decoding correctness. Tested in live-e2e.
- Multi-modal `apply_chat_template` integration. Tested in live-e2e.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SIDECAR_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SIDECAR_ROOT))

import start  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    """Build a TestClient against the FastAPI app without loading the model.

    `start.model_id` is module-level state read by `/v1/models`. The
    `__main__` block in start.py is what triggers the AutoProcessor and
    AutoModel loads; importing the module on its own does not. We set
    `model_id` here so the endpoint can report what a real production
    boot would have reported.
    """
    start.model_id = "google/gemma-4-E4B-it"
    return TestClient(start.app)


def test_models_endpoint_returns_openai_envelope(client: TestClient) -> None:
    response = client.get("/v1/models")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["object"] == "list"
    assert isinstance(body["data"], list)
    assert len(body["data"]) == 1
    entry = body["data"][0]
    assert entry["id"] == "google/gemma-4-E4B-it"
    assert entry["object"] == "model"
    assert isinstance(entry["created"], int)
    assert entry["owned_by"] == "local"


def test_models_endpoint_reports_configured_id(client: TestClient) -> None:
    start.model_id = "an-arbitrary-model-name"
    response = client.get("/v1/models")
    assert response.status_code == 200
    assert response.json()["data"][0]["id"] == "an-arbitrary-model-name"


def test_start_module_exposes_expected_helpers() -> None:
    """Pin the public surface of start.py against accidental rename.

    witness-inference's HTTP client does not import these directly, but the
    live-e2e workflow drives the server through them. Naming drift would
    surface here at PR time instead of at release time.
    """
    for name in (
        "app",
        "model_id",
        "_decode_image",
        "_decode_audio_waveform",
        "_prepare_messages",
        "list_models",
        "chat_completions",
    ):
        assert hasattr(start, name), f"start.py is missing top-level name {name!r}"
