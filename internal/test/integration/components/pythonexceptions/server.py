# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Flask and FastAPI handlers whose exceptions escape to the framework.

/truth/<token> returns the type, message and traceback CPython recorded for the
request, which the live test compares with the captured exception.
"""

import asyncio
import contextvars
import ctypes
import sys
import threading
import traceback

truths = {}

set_object = ctypes.pythonapi.PyErr_SetObject
set_object.argtypes = [ctypes.py_object, ctypes.py_object]
set_object.restype = None


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
    if case == "native-int":
        set_object(ValueError, 42)
    if case == "stop":
        next(iter(()))
    raise ValueError(token)


def middle(case, token):
    leaf(case, token)


def outer(case, token):
    middle(case, token)


def lookup(name):
    # A frame that names the error it raises keeps it alive until collected.
    error = LookupError(name)
    raise error


def fail_replacement(token):
    raise RuntimeError(token)


def render(name):
    """A template helper that re-raises the loader's error."""
    try:
        return lookup(name)
    except LookupError as error:
        raise error


def error_page(reraise=False):
    """Falls back to text when the 500 template is missing, as Django does."""
    try:
        return render("500.html") if reraise else lookup("500.html")
    except LookupError:
        return "Server Error (500)"


def evict(key, nested=False):
    try:
        lookup(key)
    except LookupError:
        if nested:
            try:
                raise OSError(key)
            except OSError:
                pass


def close():
    try:
        raise ConnectionError("already closed")
    except ConnectionError:
        pass


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
    elif case == "implicit_replacement":
        try:
            outer("ascii", token)
        except ValueError:
            lookup(token)
    elif case in ("nested_cleanup", "double_nested_cleanup"):
        try:
            outer("ascii", token)
        except ValueError:
            try:
                fail_replacement(token)
            finally:
                evict(token, nested=case == "double_nested_cleanup")
    elif case == "with_traceback":
        try:
            outer("ascii", token)
        except ValueError as error:
            raise RuntimeError(token).with_traceback(error.__traceback__) from error
    elif case == "cleanup":
        try:
            outer("ascii", token)
        finally:
            evict(token)
    elif case == "finally":
        try:
            raise ValueError(token)
        finally:
            close()
    elif case == "open":
        try:
            token + 1
        finally:
            with open(__file__) as source:
                source.readline()
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
        if case in ("error_page", "error_page_reraise"):
            error_page(reraise=case == "error_page_reraise")
        raise


def context_escape(case, token):
    contextvars.ContextVar("request").set(token)
    escape(case, token)


def handled(case, token):
    try:
        invoke(case, token)
    except Exception as error:
        truths[token] = ground_truth(error)


reuse_waiting, reuse_freed, reuse_held, reuse_sent = (threading.Event() for _ in range(4))
reuse_ids = {}


def local_errors(token, reraise):
    try:
        outer("ascii", token)
    except ValueError:
        close()
    try:
        raise LookupError(token)
    except LookupError:
        close()
        if reraise:
            raise


def cleanup_errors(token):
    """Re-raises the original error after its cleanup catches two others."""
    try:
        outer("ascii", token)
    except ValueError:
        evict(token, nested=True)
        raise


def reuse_freed_first(token, respond):
    """Answers 500 after the caught exception is freed."""
    reuse_waiting.wait(5)
    try:
        outer("ascii", token)
    except ValueError as error:
        reuse_ids["freed"] = id(error)
    reuse_freed.set()
    reuse_held.wait(5)
    respond(500, "error")
    reuse_sent.set()


def reuse_held_second(token, respond):
    """Raises at the same line through another caller, likely at the freed
    exception's address, and holds it until both requests answer."""
    reuse_waiting.set()
    reuse_freed.wait(5)
    try:
        leaf("ascii", token)
    except ValueError as error:
        truths[token] = dict(ground_truth(error), reused=id(error) == reuse_ids.get("freed"))
        reuse_held.set()
        reuse_sent.wait(5)
        respond(500, "error")


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

    async def handoff(scope, receive, send):
        token = scope["path"].rsplit("/", 1)[-1]

        def worker():
            try:
                outer("ascii", token)
            except ValueError as error:
                return error

        error = await asyncio.to_thread(worker)
        try:
            raise error
        except ValueError:
            response = PlainTextResponse("error", status_code=500)
            await response(scope, receive, send)

    app.mount("/handoff", handoff)

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
            if record.__dict__.get("native_error", False):
                try:
                    int("helper")
                except ValueError:
                    pass
                return record.getMessage()
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
            if parts[1] == "saved-error":
                try:
                    if parts[2] == "cleanup":
                        cleanup_errors(parts[3])
                    else:
                        local_errors(parts[3], reraise=parts[2] == "reraise")
                except LookupError:
                    self.respond(500, "error")
                    return
                except ValueError:
                    pass
                self.respond(500, "error")
                return
            if parts[1] == "reuse":
                reuse = reuse_freed_first if parts[2] == "freed" else reuse_held_second
                reuse(parts[3], self.respond)
                return
            try:
                if parts[1] == "raise":
                    if parts[2] == "context":
                        contextvars.Context().run(context_escape, parts[3], parts[4])
                    else:
                        escape(parts[3], parts[4])
            except Exception:
                if parts[2] == "native-helper":
                    logger.exception("request failed", extra={"native_error": True})
                elif parts[2] != "direct":
                    logger.exception("request failed")
                self.respond(500, "error")
                return
            self.respond(200, "ok")

        def log_message(self, format, *args):
            if not self.path.startswith(("/raise/direct/", "/raise/native-helper/", "/saved-error/")):
                logger.info(format, *args)

    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    framework, port = sys.argv[1], int(sys.argv[2])
    apps = {"flask": flask_app, "fastapi": fastapi_app, "http": http_app}
    apps[framework](port)
