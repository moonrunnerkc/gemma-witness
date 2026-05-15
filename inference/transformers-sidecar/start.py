#!/usr/bin/env python3
"""OpenAI-compatible FastAPI sidecar for Gemma 4 E4B using Transformers.

This sidecar accepts the same OpenAI-shaped requests as the mlx-vlm path
(text + image_url + input_audio content parts) and routes them into the
Gemma 4 multimodal processor as actual audio waveforms, not stringified
paths. Cross-platform: CPU works; CUDA / bfloat16 used when available.
"""

import argparse
import base64
import io
import json
import os
import re
import sys
import time
import uuid
from typing import Any

import numpy as np
import torch
import torchaudio
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from PIL import Image
from transformers import AutoModelForImageTextToText, AutoProcessor

TARGET_SAMPLE_RATE = 16000

app = FastAPI()
processor: Any = None
model: Any = None
model_id: str = ""


def _decode_image(source: str) -> Image.Image:
    """Decode an OpenAI-shaped image source (data URI, file URL, or path)."""
    if source.startswith("data:"):
        try:
            _, b64 = source.split(",", 1)
        except ValueError as exc:
            raise ValueError(f"malformed image data URI: {exc}")
        try:
            raw = base64.b64decode(b64)
        except Exception as exc:
            raise ValueError(f"failed to decode base64 image: {exc}")
        return Image.open(io.BytesIO(raw)).convert("RGB")
    if source.startswith("file://"):
        source = source[7:]
    if not os.path.isfile(source):
        raise ValueError(f"image path does not exist: {source}")
    return Image.open(source).convert("RGB")


def _decode_audio_waveform(source: str) -> np.ndarray:
    """Load audio bytes from a path or data URI and return a 16 kHz mono float32 waveform.

    The bytes hashed for the manifest are the bytes on disk; this resample is
    in-memory only and never modifies the asset.
    """
    if source.startswith("data:"):
        try:
            _, b64 = source.split(",", 1)
        except ValueError as exc:
            raise ValueError(f"malformed audio data URI: {exc}")
        try:
            raw = base64.b64decode(b64)
        except Exception as exc:
            raise ValueError(f"failed to decode base64 audio: {exc}")
        buffer = io.BytesIO(raw)
        waveform, sample_rate = torchaudio.load(buffer)
    else:
        if source.startswith("file://"):
            source = source[7:]
        if not os.path.isfile(source):
            raise ValueError(f"audio path does not exist: {source}")
        waveform, sample_rate = torchaudio.load(source)

    if waveform.shape[0] > 1:
        waveform = waveform.mean(dim=0, keepdim=True)
    if sample_rate != TARGET_SAMPLE_RATE:
        resampler = torchaudio.transforms.Resample(
            orig_freq=sample_rate, new_freq=TARGET_SAMPLE_RATE
        )
        waveform = resampler(waveform)
    return waveform.squeeze(0).to(torch.float32).numpy()


def _prepare_messages(
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[Image.Image], list[np.ndarray]]:
    """Convert the OpenAI-shaped messages into chat-template messages plus
    parallel lists of image PIL objects and audio numpy arrays."""
    messages = body.get("messages", [])
    tools = body.get("tools")
    text_messages: list[dict[str, Any]] = []
    images: list[Image.Image] = []
    audios: list[np.ndarray] = []
    tools_text = ""
    if tools:
        tools_text = (
            "You have access to the following tools. Use them when needed. "
            + json.dumps(tools, ensure_ascii=False)
        )

    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, str):
            if role == "system" and tools_text:
                text_messages.append({"role": role, "content": tools_text + " " + content})
            else:
                text_messages.append({"role": role, "content": content})
            continue
        if isinstance(content, list):
            chat_parts: list[dict[str, Any]] = []
            for part in content:
                ptype = part.get("type")
                if ptype == "text" or ptype == "input_text":
                    chat_parts.append({"type": "text", "text": part.get("text", "")})
                elif ptype == "image_url":
                    url = part.get("image_url", {}).get("url", "")
                    try:
                        images.append(_decode_image(url))
                    except ValueError as exc:
                        raise HTTPException(status_code=400, detail=str(exc))
                    chat_parts.append({"type": "image"})
                elif ptype == "input_audio":
                    src = part.get("input_audio", {}).get("data", "")
                    if not isinstance(src, str) or not src:
                        raise HTTPException(
                            status_code=400, detail="input_audio.data must be a non-empty string"
                        )
                    try:
                        audios.append(_decode_audio_waveform(src))
                    except ValueError as exc:
                        raise HTTPException(status_code=400, detail=str(exc))
                    chat_parts.append({"type": "audio"})
                else:
                    raise HTTPException(
                        status_code=400, detail=f"unsupported content type: {ptype}"
                    )
            if role == "system" and tools_text:
                chat_parts.insert(0, {"type": "text", "text": tools_text})
            text_messages.append({"role": role, "content": chat_parts})
        else:
            raise HTTPException(
                status_code=400, detail="message content must be a string or a list of parts"
            )

    if tools_text and not any(m.get("role") == "system" for m in text_messages):
        text_messages.insert(
            0, {"role": "system", "content": [{"type": "text", "text": tools_text}]}
        )

    return text_messages, images, audios


@app.get("/v1/models")
async def list_models() -> JSONResponse:
    return JSONResponse(
        {
            "object": "list",
            "data": [
                {
                    "id": model_id,
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "local",
                }
            ],
        }
    )


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}")

    text_messages, images, audios = _prepare_messages(body)

    temperature = body.get("temperature", 0.7)
    max_tokens = body.get("max_tokens", 1024)
    top_p = body.get("top_p", 1.0)

    try:
        inputs = processor.apply_chat_template(
            text_messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
            images=images if images else None,
            audio=audios if audios else None,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"apply_chat_template failed: {exc}"
        )

    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    prompt_len = inputs["input_ids"].shape[1]

    gen_kwargs: dict[str, Any] = {
        "max_new_tokens": max_tokens,
        "do_sample": temperature > 0,
    }
    if temperature > 0:
        gen_kwargs["temperature"] = temperature
    if top_p < 1.0:
        gen_kwargs["top_p"] = top_p

    try:
        with torch.no_grad():
            outputs = model.generate(**inputs, **gen_kwargs)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"model generation failed: {exc}")

    new_tokens = outputs[0][prompt_len:]
    try:
        decoded = processor.decode(new_tokens, skip_special_tokens=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"decoding failed: {exc}")

    content = decoded
    reasoning: str | None = None
    think_match = re.search(r"\n\nReasoning process:\n.*?\n\n", decoded, re.DOTALL)
    if think_match:
        reasoning = think_match.group(0).strip()
        content = re.sub(r"\n\nReasoning process:\n.*?\n\n", "", decoded, flags=re.DOTALL).strip()

    tool_calls = None
    if body.get("tools"):
        try:
            m = re.search(r"\{.*", content, re.DOTALL)
            if m:
                parsed = json.loads(m.group(0))
                if isinstance(parsed, list) and parsed:
                    tool_calls = [
                        {
                            "id": f"call_{uuid.uuid4().hex[:12]}",
                            "type": "function",
                            "function": t,
                        }
                        for t in parsed
                    ]
                elif isinstance(parsed, dict) and "name" in parsed:
                    tool_calls = [
                        {
                            "id": f"call_{uuid.uuid4().hex[:12]}",
                            "type": "function",
                            "function": parsed,
                        }
                    ]
                if tool_calls:
                    content = ""
        except (json.JSONDecodeError, ValueError):
            pass

    message: dict[str, Any] = {"role": "assistant"}
    if content:
        message["content"] = content
    if reasoning:
        message["reasoning"] = reasoning
    if tool_calls:
        message["tool_calls"] = tool_calls

    return JSONResponse(
        {
            "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model_id,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_len,
                "completion_tokens": len(new_tokens),
                "total_tokens": prompt_len + len(new_tokens),
            },
        }
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="transformers sidecar for Gemma 4 E4B")
    parser.add_argument("--model", default="google/gemma-4-E4B-it")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    model_id = args.model

    print(f"loading {model_id} processor...", flush=True)
    try:
        processor = AutoProcessor.from_pretrained(model_id)
    except Exception as exc:
        print(f"failed to load processor for {model_id}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"loading {model_id} model...", flush=True)
    try:
        dtype = torch.bfloat16 if torch.cuda.is_available() else torch.float32
        model = AutoModelForImageTextToText.from_pretrained(
            model_id,
            torch_dtype=dtype,
            device_map="auto",
        )
    except Exception as exc:
        print(f"failed to load model {model_id}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"ready at http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
