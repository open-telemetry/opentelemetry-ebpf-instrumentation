# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from fastapi import FastAPI
import os
import uvicorn
import requests

app = FastAPI()

JEV_BASE_URL = os.environ.get("JEV_BASE_URL", "http://localhost:8084")
JEV_MODEL = "jev-1.13"


def _headers():
    return {"Content-Type": "application/json"}


@app.get("/health")
async def health():
    return "ok!"


@app.get("/decision")
async def decision():
    """Send a decision evaluation request to Jev"""
    url = f"{JEV_BASE_URL}/api/v1/systemone"
    payload = {
        "model": JEV_MODEL,
        "state": "Order #8814 arrived with a cracked screen.",
        "questions": {
            "refund_requested": {
                "type": "noul",
                "instructions": "Is the customer asking for a refund?"
            }
        }
    }
    resp = requests.post(url, json=payload, headers=_headers())
    resp.raise_for_status()
    return resp.json()


@app.get("/choice")
async def choice_decision():
    """Send a choice-type question request to Jev"""
    url = f"{JEV_BASE_URL}/api/v1/systemone"
    payload = {
        "model": JEV_MODEL,
        "state": "Customer wants to return an item that arrived damaged.",
        "questions": {
            "refund_action": {
                "type": "choice",
                "instructions": "What refund action should be taken?",
                "choices": ["full_refund", "partial_refund", "no_refund"]
            }
        }
    }
    resp = requests.post(url, json=payload, headers=_headers())
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    print(f"Jev test server running: port=8080 pid={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
