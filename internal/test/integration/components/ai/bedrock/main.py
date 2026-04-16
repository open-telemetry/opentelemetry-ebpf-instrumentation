from fastapi import FastAPI
import os
import uvicorn
import requests

app = FastAPI()

BEDROCK_BASE_URL = os.environ.get("BEDROCK_BASE_URL", "http://localhost:8086")
CLAUDE_MODEL = "anthropic.claude-3-5-sonnet-20241022-v1:0"
TITAN_MODEL = "amazon.titan-text-premier-v1:0"


def _headers():
    return {"Content-Type": "application/json"}


@app.get("/health")
async def health():
    return "ok!"


@app.get("/claude")
async def invoke_claude():
    url = f"{BEDROCK_BASE_URL}/model/{CLAUDE_MODEL}/invoke"
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1024,
        "system": "You are a helpful assistant.",
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": "Explain eBPF in two sentences."}],
            }
        ],
        "temperature": 0.7,
        "top_p": 0.9,
    }
    resp = requests.post(url, json=payload, headers=_headers())
    resp.raise_for_status()
    return resp.json()


@app.get("/titan")
async def invoke_titan():
    url = f"{BEDROCK_BASE_URL}/model/{TITAN_MODEL}/invoke"
    payload = {
        "inputText": "Explain eBPF in two sentences.",
        "textGenerationConfig": {
            "maxTokenCount": 512,
            "temperature": 0.7,
            "topP": 0.9,
        },
    }
    resp = requests.post(url, json=payload, headers=_headers())
    resp.raise_for_status()
    return resp.json()


@app.get("/error")
async def invoke_error():
    url = f"{BEDROCK_BASE_URL}/model/anthropic.claude-nonexistent/invoke"
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Hello"}]}],
    }
    resp = requests.post(url, json=payload, headers=_headers())
    return resp.json()


if __name__ == "__main__":
    print(f"Bedrock test server running: port=8080 pid={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
