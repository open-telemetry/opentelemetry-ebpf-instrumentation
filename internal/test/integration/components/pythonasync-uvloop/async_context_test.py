from fastapi import FastAPI
import httpx
import asyncio
import requests
import os

app = FastAPI()
http_client = None
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8085")


@app.on_event("startup")
async def startup():
    global http_client
    http_client = httpx.AsyncClient(timeout=30.0)
    loop = asyncio.get_running_loop()
    loop_class = f"{loop.__class__.__module__}.{loop.__class__.__name__}"
    is_uvloop = "uvloop" in loop.__class__.__module__.lower()
    print(
        f"[startup] asyncio loop in use: {loop_class} "
        f"({'uvloop' if is_uvloop else 'non-uvloop'})",
        flush=True,
    )


@app.on_event("shutdown")
async def shutdown():
    await http_client.aclose()


@app.get("/sequential/{req_id}")
async def test_sequential(req_id: int):
    r1 = await http_client.get(f"{BACKEND_URL}/")
    r2 = await http_client.get(f"{BACKEND_URL}/")
    r3 = await http_client.get(f"{BACKEND_URL}/")
    return {"id": req_id, "calls": 3, "status_codes": [r1.status_code, r2.status_code, r3.status_code]}


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.get("/to-thread/{req_id}")
async def test_to_thread(req_id: int):
    def blocking_http_call(url: str):
        response = requests.get(url, timeout=30)
        return response.status_code

    r1 = await asyncio.to_thread(blocking_http_call, f"{BACKEND_URL}/")
    r2 = await asyncio.to_thread(blocking_http_call, f"{BACKEND_URL}/")
    return {"id": req_id, "calls": 2, "status_codes": [r1, r2]}


@app.get("/concurrent/{req_id}")
async def test_concurrent(req_id: int):
    r1, r2, r3 = await asyncio.gather(
        http_client.get(f"{BACKEND_URL}/"),
        http_client.get(f"{BACKEND_URL}/"),
        http_client.get(f"{BACKEND_URL}/"),
    )
    return {"id": req_id, "calls": 3, "status_codes": [r1.status_code, r2.status_code, r3.status_code]}


@app.get("/nested/{req_id}")
async def test_nested(req_id: int):
    async def leaf_call():
        response = await http_client.get(f"{BACKEND_URL}/")
        return response.status_code

    async def middle():
        t1 = asyncio.create_task(leaf_call())
        t2 = asyncio.create_task(leaf_call())
        r1, r2 = await asyncio.gather(t1, t2)
        return [r1, r2]

    top = asyncio.create_task(middle())
    results = await top
    return {"id": req_id, "calls": 2, "status_codes": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn_loop = os.environ.get("UVICORN_LOOP", "uvloop")
    print(f"[boot] UVICORN_LOOP={uvicorn_loop}", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=8391, loop=uvicorn_loop)
