# A plain asyncio.start_server HTTP service (no web framework): the handler
# task is created once per connection from a plain loop callback, the shape
# that exercises generic asyncio context propagation. Outbound calls use a
# unique downstream path per request id and call index (e.g. /seq/7/2) so the
# integration test can assert the exact client-span set per server trace.
import asyncio
import json
import os
import sys

import httpx
import requests

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8085")
PORT = int(os.environ.get("PORT", "8392"))

http_client = None


def _response(status: int, body: dict, keep_alive: bool) -> bytes:
    payload = json.dumps(body).encode()
    reason = {200: "OK", 404: "Not Found", 500: "Internal Server Error"}.get(
        status, "OK"
    )
    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n"
        f"\r\n"
    )
    return headers.encode() + payload


async def handle_sequential(req_id: str):
    codes = []
    for call in (1, 2, 3):
        r = await http_client.get(f"{BACKEND_URL}/seq/{req_id}/{call}")
        codes.append(r.status_code)
    return {"id": req_id, "calls": 3, "status_codes": codes}


async def handle_concurrent(req_id: str):
    r1, r2, r3 = await asyncio.gather(
        http_client.get(f"{BACKEND_URL}/conc/{req_id}/1"),
        http_client.get(f"{BACKEND_URL}/conc/{req_id}/2"),
        http_client.get(f"{BACKEND_URL}/conc/{req_id}/3"),
    )
    return {
        "id": req_id,
        "calls": 3,
        "status_codes": [r1.status_code, r2.status_code, r3.status_code],
    }


async def handle_nested(req_id: str):
    async def leaf_call(call: int):
        response = await http_client.get(f"{BACKEND_URL}/nest/{req_id}/{call}")
        return response.status_code

    async def middle():
        t1 = asyncio.create_task(leaf_call(1))
        t2 = asyncio.create_task(leaf_call(2))
        return list(await asyncio.gather(t1, t2))

    results = await asyncio.create_task(middle())
    return {"id": req_id, "calls": 2, "status_codes": results}


async def handle_to_thread(req_id: str):
    def blocking_http_call(url: str):
        response = requests.get(url, timeout=30)
        return response.status_code

    r1 = await asyncio.to_thread(
        blocking_http_call, f"{BACKEND_URL}/thr/{req_id}/1"
    )
    r2 = await asyncio.to_thread(
        blocking_http_call, f"{BACKEND_URL}/thr/{req_id}/2"
    )
    return {"id": req_id, "calls": 2, "status_codes": [r1, r2]}


ROUTES = {
    "sequential": handle_sequential,
    "concurrent": handle_concurrent,
    "nested": handle_nested,
    "to-thread": handle_to_thread,
}


async def dispatch(path: str):
    if path == "/health":
        return 200, {"status": "ok"}
    parts = path.strip("/").split("/")
    if len(parts) == 2 and parts[0] in ROUTES:
        return 200, await ROUTES[parts[0]](parts[1])
    return 404, {"error": "not found", "path": path}


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Keep-alive loop: one handler task serves every request on this connection
    try:
        while True:
            try:
                raw = await reader.readuntil(b"\r\n\r\n")
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            request_line = raw.split(b"\r\n", 1)[0].decode("latin-1")
            fields = request_line.split(" ")
            if len(fields) != 3:
                break
            _, path, _ = fields
            headers = raw.decode("latin-1").lower()
            keep_alive = "connection: close" not in headers

            try:
                status, body = await dispatch(path)
            except Exception as exc:  # noqa: BLE001
                status, body = 500, {"error": str(exc)}

            writer.write(_response(status, body, keep_alive))
            await writer.drain()
            if not keep_alive:
                break
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass


async def main():
    global http_client
    http_client = httpx.AsyncClient(timeout=30.0)

    loop = asyncio.get_running_loop()
    loop_class = f"{loop.__class__.__module__}.{loop.__class__.__name__}"
    print(f"[startup] asyncio loop in use: {loop_class}", flush=True)

    server = await asyncio.start_server(handle_connection, host="0.0.0.0", port=PORT)
    print(f"[startup] asyncio.start_server listening on :{PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    loop_impl = os.environ.get("LOOP", "asyncio")
    print(f"[boot] LOOP={loop_impl}", flush=True)
    if loop_impl == "uvloop":
        import uvloop

        uvloop.run(main())
    else:
        asyncio.run(main())
