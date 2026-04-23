# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from fastapi import FastAPI
import os
import uvicorn
import requests

app = FastAPI()

QWEN_BASE_URL = os.environ.get("QWEN_BASE_URL", "http://localhost:8085")

HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer test-key",
}


@app.get("/health")
async def health():
    return "ok!"


@app.get("/chat")
async def chat():
    payload = {
        "model": "qwen-plus",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "你是谁？"},
        ],
    }
    resp = requests.post(
        f"{QWEN_BASE_URL}/compatible-mode/v1/chat/completions",
        json=payload,
        headers=HEADERS,
    )
    resp.raise_for_status()
    return resp.json()


@app.get("/generation")
async def generation():
    payload = {
        "model": "qwen-turbo",
        "prompt": "Explain eBPF in one sentence.",
    }
    resp = requests.post(
        f"{QWEN_BASE_URL}/api/v1/services/aigc/text-generation/generation",
        json=payload,
        headers=HEADERS,
    )
    resp.raise_for_status()
    return resp.json()


@app.get("/error")
async def error():
    payload = {
        "model": "qwen-plus",
        "messages": [
            {"role": "user", "content": "trigger error"},
        ],
    }
    resp = requests.post(
        f"{QWEN_BASE_URL}/compatible-mode/v1/chat/completions?error=true",
        json=payload,
        headers=HEADERS,
    )
    # OATS expects the application endpoint to return 200 for request triggering.
    # Keep upstream error payload, but normalize response status to 200.
    return resp.json()


if __name__ == "__main__":
    print(f"Qwen test server running: port=8080 process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
