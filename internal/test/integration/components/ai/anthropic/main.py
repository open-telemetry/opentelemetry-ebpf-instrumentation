from fastapi import FastAPI, Request
import os
import uvicorn
import requests
import json

app = FastAPI()

ANTHROPIC_BASE_URL = os.environ.get("ANTHROPIC_BASE_URL", "http://localhost:8082")

HEADERS = {
    "x-api-key": "sk-ant-test",
    "anthropic-version": "2023-06-01",
    "content-type": "application/json",
    "accept": "application/json",
}

@app.get("/health")
async def health():
    return "ok!"

@app.get("/messages")
async def messages():
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "Explain quantum computing in one sentence."}],
    }
    resp = requests.post(f"{ANTHROPIC_BASE_URL}/v1/messages", json=payload, headers=HEADERS)
    resp.raise_for_status()
    return resp.json()

@app.get("/stream")
async def stream():
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "Write a two-line poem about Python programming."}],
        "stream": True,
    }
    resp = requests.post(
        f"{ANTHROPIC_BASE_URL}/v1/messages",
        json=payload,
        headers={**HEADERS, "accept": "text/event-stream"},
        stream=True,
    )
    resp.raise_for_status()

    text = ""
    for line in resp.iter_lines():
        if not line:
            continue
        decoded = line.decode("utf-8") if isinstance(line, bytes) else line
        if decoded.startswith("data: "):
            data = json.loads(decoded[6:])
            if data.get("type") == "content_block_delta":
                delta = data.get("delta", {})
                if delta.get("type") == "text_delta":
                    text += delta.get("text", "")
    return {"text": text}

@app.get("/multi-turn")
async def multi_turn():
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 100,
        "messages": [
            {"role": "user", "content": "What is the capital of France?"},
            {"role": "assistant", "content": "The capital of France is **Paris**."},
            {"role": "user", "content": "What is its population?"},
            {"role": "assistant", "content": "The population of **Paris** is approximately 2.1 million in the city proper."},
            {"role": "user", "content": "Name a famous landmark there."},
        ],
    }
    resp = requests.post(f"{ANTHROPIC_BASE_URL}/v1/messages", json=payload, headers=HEADERS)
    resp.raise_for_status()
    return resp.json()

@app.get("/system")
async def system_prompt():
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 100,
        "system": "You are a helpful assistant that always responds in haiku format.",
        "messages": [{"role": "user", "content": "Tell me about the ocean."}],
    }
    resp = requests.post(f"{ANTHROPIC_BASE_URL}/v1/messages", json=payload, headers=HEADERS)
    resp.raise_for_status()
    return resp.json()

@app.get("/tools")
async def tools():
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "tools": [
            {
                "name": "get_weather",
                "description": "Get the current weather in a given location",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string", "description": "The city and state, e.g. San Francisco, CA"},
                        "unit": {"type": "string", "enum": ["celsius", "fahrenheit"], "description": "The unit of temperature"},
                    },
                    "required": ["location"],
                },
            }
        ],
        "messages": [
            {"role": "user", "content": "What's the weather like in Paris?"},
            {
                "role": "assistant",
                "content": [
                    {"text": "Let me check the current weather in Paris for you!", "type": "text"},
                    {"id": "toolu_01PgoXSLv6kZQhcswcbgswFb", "input": {"location": "Paris, France"}, "name": "get_weather", "type": "tool_use"},
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01PgoXSLv6kZQhcswcbgswFb",
                        "content": '{"temperature": 18, "unit": "celsius", "condition": "partly cloudy"}',
                    }
                ],
            },
        ],
    }
    resp = requests.post(f"{ANTHROPIC_BASE_URL}/v1/messages", json=payload, headers=HEADERS)
    resp.raise_for_status()
    return resp.json()

@app.get("/error")
async def error_messages():
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "Explain quantum computing in one sentence."}],
    }
    resp = requests.post(f"{ANTHROPIC_BASE_URL}/v1/messages?error", json=payload, headers=HEADERS)
    return resp.json()

if __name__ == "__main__":
    print(f"Server running: port={8081} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8081)
