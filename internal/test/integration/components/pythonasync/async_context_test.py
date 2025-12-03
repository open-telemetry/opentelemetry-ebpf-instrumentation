import asyncio
from aiohttp import web
import httpx
import requests
import os

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8085")


async def startup(app: web.Application):
    app["http_client"] = httpx.AsyncClient(timeout=30.0)


async def shutdown(app: web.Application):
    await app["http_client"].aclose()


async def test_sequential(request: web.Request) -> web.Response:
    req_id = int(request.match_info["req_id"])
    http_client = request.app["http_client"]
    r1 = await http_client.get(f"{BACKEND_URL}/")
    r2 = await http_client.get(f"{BACKEND_URL}/")
    r3 = await http_client.get(f"{BACKEND_URL}/")
    return web.json_response(
        {"id": req_id, "calls": 3, "status_codes": [r1.status_code, r2.status_code, r3.status_code]}
    )


async def health_check(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def test_to_thread(request: web.Request) -> web.Response:
    req_id = int(request.match_info["req_id"])

    def blocking_http_call(url: str):
        response = requests.get(url, timeout=30)
        return response.status_code

    r1 = await asyncio.to_thread(blocking_http_call, f"{BACKEND_URL}/")
    r2 = await asyncio.to_thread(blocking_http_call, f"{BACKEND_URL}/")
    return web.json_response({"id": req_id, "calls": 2, "status_codes": [r1, r2]})


async def test_parallel(request: web.Request) -> web.Response:
    req_id = int(request.match_info["req_id"])
    http_client = request.app["http_client"]
    r1, r2, r3 = await asyncio.gather(
        http_client.get(f"{BACKEND_URL}/"),
        http_client.get(f"{BACKEND_URL}/"),
        http_client.get(f"{BACKEND_URL}/")
    )
    return web.json_response(
        {"id": req_id, "calls": 3, "status_codes": [r1.status_code, r2.status_code, r3.status_code]}
    )


async def test_create_task(request: web.Request) -> web.Response:
    req_id = int(request.match_info["req_id"])
    http_client = request.app["http_client"]

    async def call(i: int):
        r = await http_client.get(f"{BACKEND_URL}/?i={i}")
        return r.status_code

    tasks = [asyncio.create_task(call(i)) for i in range(3)]
    codes = await asyncio.gather(*tasks)
    return web.json_response({"id": req_id, "calls": len(tasks), "status_codes": codes})


def create_app() -> web.Application:
    app = web.Application()
    app.on_startup.append(startup)
    app.on_cleanup.append(shutdown)
    app.router.add_get("/sequential/{req_id}", test_sequential)
    app.router.add_get("/health", health_check)
    app.router.add_get("/to-thread/{req_id}", test_to_thread)
    app.router.add_get("/parallel/{req_id}", test_parallel)
    app.router.add_get("/create-task/{req_id}", test_create_task)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8391)
