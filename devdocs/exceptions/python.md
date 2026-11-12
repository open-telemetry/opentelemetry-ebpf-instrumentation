# Python exceptions

OBI captures CPython exceptions from instrumented processes with exception
capture enabled. Request exceptions are emitted when OBI observes a server
response with status 500 or higher.

## Configuration

Use Config v2 and configure a logs exporter as shown in [README.md](README.md):

```yaml
extensions:
  obi:
    version: "2.0"
    capture:
      exceptions:
        enabled: true
```

A workload rule can override `refine.exceptions.enabled`. Python currently uses
this shared switch for request capture and has no language-specific options.

## Probes

| Function | Probe | Captures |
|---|---|---|
| `_PyErr_SetObject` | entry | exception candidates for the active request |

The probe is attached per process, and only to processes that capture exceptions.
Exceptions raised before OBI attaches to a process are not captured.

OBI keeps bounded candidate state and uses traceback propagation to select an
exception when the server response arrives. Selection uses a heuristic for
exceptions that escape handlers.

## What is captured

| Python code / behavior | Record | `exception.message` |
|---|---|---|
| Handler raises `ValueError("bad input")` and the framework responds 500 | `ValueError`, severity ERROR | `bad input` |
| Handler catches the exception locally and returns 500 | none in the integration fixture | |
| Handler responds successfully | none | |
| Standalone uncaught exception | none | |
| Standalone caught exception | none | |

Records use the shared `exception.type`, `exception.message` and
`exception.stacktrace` attributes. BPF captures up to 256 bytes of Python string
storage. Python uses one-, two- or four-byte Unicode code units; user space
converts these to UTF-8. OBI reads stored exception arguments and does not execute
custom `__str__` methods. Message rendering can therefore differ from Python's
rendering for custom exceptions and unsupported argument shapes.

## Stack traces

The probe walks an existing traceback when available, otherwise the active
Python frames. It retains up to 24 frames; traversal is bounded to 32 active
frames or 128 traceback entries. User space reads code objects and line tables
from the target process and formats a Python traceback.

`exception.stacktrace` lists frames outermost first and ends with the exception
type and message:

```text
Traceback (most recent call last):
  File "/app/server.py", line 42, in handler
ValueError: bad input
```

### Known limits

- Cause chains and nested exception groups are not expanded into separate
  tracebacks.
- Decoding requires readable target memory. Process exit or object reclamation
  before decoding can lose type or frame information. PID reuse and decoding
  after exit require further lifecycle work.

## Request association

Request ownership uses the existing asyncio task/context tracking, with a
thread-based fallback. Capturing arbitrary background exceptions through
`_PyErr_SetObject` requires an active request owner.

Current live validation covers Linux amd64, CPython 3.9-3.14:

- Slim images: Flask and threaded HTTP.
- Full Python 3.13/3.14 images and the Python 3.14 static build: additionally
  FastAPI await, child-task, thread-pool and concurrent request cases.
- Python 3.14 LTO: Flask and threaded HTTP.
- Free-threaded builds: capture rejection.

FastAPI on slim and LTO builds is deferred. Those cases explicitly skip in the
matrix. Missing task symbols can cause incorrect request association through the
thread fallback; a skip does not disable that production path. ARM64 runtime
capture has not been validated. Hidden `_PyErr_SetObject` derivation supports
amd64 only.
