from fastapi import FastAPI
import os
import uvicorn
import requests

app = FastAPI()

GEMINI_BASE_URL = os.environ.get("GEMINI_BASE_URL", "http://localhost:8083")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-2.0-flash"


def _headers():
    if GEMINI_API_KEY:
        return {"X-Goog-Api-Key": GEMINI_API_KEY, "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


@app.get("/health")
async def health():
    return "ok!"


@app.get("/generate")
async def generate():
    url = f"{GEMINI_BASE_URL}/v1beta/models/{GEMINI_MODEL}:generateContent"
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": "Explain eBPF in two sentences."}],
            }
        ],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 128,
        },
    }
    resp = requests.post(url, json=payload, headers=_headers())
    resp.raise_for_status()
    return resp.json()


@app.get("/system")
async def system_instruction():
    url = f"{GEMINI_BASE_URL}/v1beta/models/{GEMINI_MODEL}:generateContent"
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": "What is the weather in San Francisco?"}],
            }
        ],
        "systemInstruction": {
            "parts": [{"text": "You are a helpful assistant. Be concise."}],
            "role": "user",
        },
        "tools": [
            {
                "functionDeclarations": [
                    {
                        "name": "get_weather",
                        "description": "Get the current weather for a location",
                        "parameters": {
                            "type": "OBJECT",
                            "properties": {
                                "location": {"type": "STRING", "description": "City name"}
                            },
                            "required": ["location"],
                        },
                    }
                ]
            }
        ],
        "generationConfig": {"temperature": 0.2},
    }
    resp = requests.post(url, json=payload, headers=_headers())
    resp.raise_for_status()
    return resp.json()


@app.get("/error")
async def error_call():
    url = f"{GEMINI_BASE_URL}/v1beta/models/gemini-nonexistent:generateContent"
    payload = {
        "contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
    }
    resp = requests.post(url, json=payload, headers=_headers())
    return resp.json()


if __name__ == "__main__":
    print(f"Gemini test server running: port=8080 pid={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
