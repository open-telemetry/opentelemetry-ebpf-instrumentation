# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Flask and FastAPI handlers whose exceptions escape to the framework.

/truth/<token> returns the type, message and traceback CPython recorded for the
request, which the live test compares with the captured exception.
"""

import asyncio
import sys
import traceback

truths = {}


class CustomError(Exception):
    pass


def leaf(case, token):
    if case == "empty":
        raise ValueError()
    if case == "unicode":
        raise ValueError("café Ελληνικά 東京 🐍 " + token)
    if case == "long":
        raise ValueError(token + "x" * 4096)
    if case == "key":
        raise KeyError(token)
    if case == "os":
        raise OSError(2, token, "/missing")
    if case == "custom":
        raise CustomError(token)
    if case == "multiarg":
        raise ValueError(token, 42)
    if case == "group":
        raise ExceptionGroup(token, [ValueError("child")])
    if case == "native":
        int(token)
    if case == "stop":
        next(iter(()))
    raise ValueError(token)


def middle(case, token):
    leaf(case, token)


def outer(case, token):
    middle(case, token)


def recursive(depth, token):
    if depth:
        recursive(depth - 1, token)
    raise ValueError(token)


def invoke(case, token):
    if case == "deep":
        recursive(40, token)
    elif case == "reraise":
        try:
            outer("ascii", token)
        except ValueError:
            raise
    elif case == "raise_error":
        try:
            outer("ascii", token)
        except ValueError as error:
            raise error
    elif case == "latest":
        try:
            raise TypeError("earlier: " + token)
        except TypeError:
            pass
        outer("ascii", token)
    elif case == "chained":
        try:
            outer("ascii", token)
        except ValueError as error:
            raise RuntimeError(token) from error
    else:
        outer(case, token)


def ground_truth(error):
    """What OBI reports: the SDK's exception.type, args[0] when it is a str
    (quoted for KeyError, as str() does) and the traceback's frames."""
    kind = type(error)
    name = kind.__qualname__ if kind.__module__ == "builtins" else f"{kind.__module__}.{kind.__qualname__}"
    message = error.args[0] if error.args and isinstance(error.args[0], str) else ""
    if kind is KeyError and message:
        message = repr(message)
    return {
        "type": name,
        "line_type": kind.__qualname__ if kind.__module__ in ("builtins", "__main__") else name,
        "message": message,
        "frames": [
            {"file": frame.f_code.co_filename, "line": line, "function": frame.f_code.co_name}
            for frame, line in traceback.walk_tb(error.__traceback__)
        ],
    }


def escape(case, token):
    try:
        invoke(case, token)
    except BaseException as error:
        truths[token] = ground_truth(error)
        raise


def handled(case, token):
    try:
        invoke(case, token)
    except Exception as error:
        truths[token] = ground_truth(error)


async def nested(case, token):
    await asyncio.sleep(0.001)
    escape(case, token)


def flask_app(port):
    from flask import Flask

    app = Flask(__name__)

    @app.get("/health")
    def health():
        return "ready"

    @app.get("/ok")
    def ok():
        return "ok"

    @app.get("/truth/<token>")
    def truth(token):
        return truths.pop(token, {})

    @app.get("/raise/sync/<case>/<token>")
    def raise_sync(case, token):
        escape(case, token)

    @app.get("/handled/sync/<case>/<token>/<int:status>")
    def handled_sync(case, token, status):
        handled(case, token)
        return "handled", status

    app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False)


def fastapi_app(port):
    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse

    app = FastAPI()

    @app.get("/health")
    def health():
        return "ready"

    @app.get("/ok")
    async def ok():
        return "ok"

    @app.get("/truth/{token}")
    def truth(token: str):
        return truths.pop(token, {})

    @app.get("/raise/await/{case}/{token}")
    async def raise_await(case: str, token: str):
        await asyncio.sleep(0.001)
        escape(case, token)

    @app.get("/raise/task/{case}/{token}")
    async def raise_task(case: str, token: str):
        await asyncio.create_task(nested(case, token))

    @app.get("/raise/thread/{case}/{token}")
    async def raise_thread(case: str, token: str):
        await asyncio.to_thread(escape, case, token)

    @app.get("/raise/sync/{case}/{token}")
    def raise_sync(case: str, token: str):
        escape(case, token)

    @app.get("/handled/{mode}/{case}/{token}/{status}")
    async def handled_await(mode: str, case: str, token: str, status: int):
        handled(case, token)
        return PlainTextResponse("handled", status_code=status)

    uvicorn.run(app, host="127.0.0.1", port=port, access_log=False, log_level="warning")


def http_app(port):
    """http.server handler that logs through the logging module while it
    answers 500, as the exception it caught is still being handled. Its
    formatter raises and catches a SyntaxError, as traceback's caret
    placement does through ast.parse."""
    import ast
    import http.server
    import json
    import logging

    class ParsingFormatter(logging.Formatter):
        def format(self, record):
            try:
                ast.parse("(")
            except SyntaxError:
                pass
            return super().format(record)

    handler = logging.StreamHandler()
    handler.setFormatter(ParsingFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    logger = logging.getLogger("fixture")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def respond(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parts = self.path.split("/")
            if parts[1] == "truth":
                self.respond(200, truths.pop(parts[2], {}))
                return
            if parts[1] == "handled":
                handled(parts[3], parts[4])
                self.respond(int(parts[5]), "handled")
                return
            try:
                if parts[1] == "raise":
                    escape(parts[3], parts[4])
            except Exception:
                if parts[2] != "direct":
                    logger.exception("request failed")
                self.respond(500, "error")
                return
            self.respond(200, "ok")

        def log_message(self, format, *args):
            if not self.path.startswith("/raise/direct/"):
                logger.info(format, *args)

    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    framework, port = sys.argv[1], int(sys.argv[2])
    apps = {"flask": flask_app, "fastapi": fastapi_app, "http": http_app}
    apps[framework](port)
