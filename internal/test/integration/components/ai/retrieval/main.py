import os
import time

import requests
import uvicorn
from fastapi import FastAPI

app = FastAPI()

QDRANT = os.environ.get("QDRANT_URL", "http://vectors.qdrant.tech:6333")
COLLECTION = os.environ.get("QDRANT_COLLECTION", "obitest")
VECTOR_SIZE = 4


def wait_for_qdrant(attempts=60, delay=1.0):
    for _ in range(attempts):
        try:
            if requests.get(f"{QDRANT}/collections", timeout=5).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(delay)
    raise RuntimeError(f"qdrant not reachable at {QDRANT}")


def ensure_collection():
    wait_for_qdrant()
    requests.put(
        f"{QDRANT}/collections/{COLLECTION}",
        json={"vectors": {"size": VECTOR_SIZE, "distance": "Cosine"}},
        timeout=30,
    )
    requests.put(
        f"{QDRANT}/collections/{COLLECTION}/points?wait=true",
        json={
            "points": [
                {"id": 1, "vector": [0.1, 0.2, 0.3, 0.4], "payload": {"kind": "obi"}},
                {"id": 2, "vector": [0.2, 0.1, 0.4, 0.3], "payload": {"kind": "obi"}},
            ]
        },
        timeout=30,
    )


@app.get("/search")
async def search():
    resp = requests.post(
        f"{QDRANT}/collections/{COLLECTION}/points/search",
        json={"vector": [0.1, 0.2, 0.3, 0.4], "limit": 3, "with_payload": True},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


@app.get("/query")
async def query():
    resp = requests.post(
        f"{QDRANT}/collections/{COLLECTION}/points/query",
        json={"query": [0.1, 0.2, 0.3, 0.4], "limit": 2, "with_payload": True},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


@app.get("/smoke")
async def smoke():
    return {"ok": True}


if __name__ == "__main__":
    ensure_collection()
    print(f"retrieval client running: port=8080 process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
