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
        python:
          enabled: true
```

`exceptions.python.enabled` defaults to `true`. Set it to `false` to disable all
Python exception capture while keeping capture for other runtimes enabled.
The shared `exceptions.enabled` switch must also be enabled for Python capture.

A workload rule can override `refine.exceptions.enabled` and
`refine.exceptions.python.enabled`. Omitted fields inherit the global settings.

## Probes

| Function | Probe | Captures |
|---|---|---|
| `_PyErr_SetObject` | entry | exception candidates for the active request |

The probe is attached per process, and only to processes that capture exceptions.
Exceptions raised before OBI attaches to a process are not captured.

OBI keeps bounded candidate state and uses traceback propagation to select an
exception when the server response arrives. Selection uses a heuristic for
exceptions that escape handlers:

- The latest exception that left the frame raising it is selected, unless it
  was raised while an earlier candidate was being handled and never left the
  frame handling that one, as when a 500 handler fails to load its error
  template. The earlier candidate is selected instead.
- An exception still being handled when another one is raised, as by a
  `finally` block that runs cleanup code, remains a candidate. It is selected
  over the earlier candidate once it is seen being handled outside the frame
  handling that one, at the response or when another exception is raised.
- A raise from C code, such as `None + 1`, is matched with the instance CPython
  creates for it by type and by the frame and instruction that raised it.
  CPython raises and clears exceptions internally, as `open()` does with a
  `TypeError`, and these do not take over the exception being handled.

An exception retained while another exception is raised can still be reported
if the request later returns 500, even when both exceptions were caught.
Traceback propagation does not establish that an exception caused the response.

## What is captured

| Python code / behavior | Record | `exception.message` |
|---|---|---|
| Handler raises `ValueError("bad input")` and the framework responds 500 | `ValueError`, severity ERROR | `bad input` |
| Handler raises `ValueError(404)` | `ValueError` | `404` |
| Handler raises `Exception("first", 2)` | `Exception` | `('first', 2)` |
| Handler raises `Exception("first", 2, {"a": 1})` | `Exception` | empty |
| Handler catches the exception locally and returns 500 | none in the integration fixture | |
| Handler responds successfully | none | |
| Standalone uncaught exception | none | |
| Standalone caught exception | none | |

Records use the shared `exception.type`, `exception.message` and
`exception.stacktrace` attributes. OBI reads the stored exception arguments and
does not execute `__str__`:

- An exception whose type keeps `BaseException.__str__` or `KeyError.__str__`
  gets what `str()` returns for no arguments, one `str` or `int` argument, or
  up to four `str` and `int` arguments, which render as their tuple. Of several
  arguments, those before the fifth or before one of another type render as the
  start of their tuple, ending in `...`. Other argument shapes give an empty
  message.
- An exception whose type defines its own `__str__` gets its first argument when
  that is a `str`, and an empty message otherwise. Its rendering can therefore
  differ from Python's.

BPF keeps up to 256 bytes of argument data for the reported exception and 128
bytes for the chained one; several arguments take equal parts. Python stores a
`str` in one-, two- or four-byte code units, chosen by its widest character, so
256 bytes hold 256, 128 or 64 characters. User space converts them to UTF-8
and ends a cut `str` in `...`. An `int` is kept only when all of its digits fit.

## Stack traces

The probe walks an existing traceback when available, otherwise the active
Python frames. When the response selects an exception that is still alive, OBI
walks its traceback again, so the stack matches CPython's traceback: from the
frame that caught the exception to the frame that raised it, including
re-raises and `with_traceback()`. It retains up to 24 frames; traversal is
bounded to 32 active frames or 128 traceback entries. User space reads code
objects and line tables from the target process and formats a Python traceback.

`exception.stacktrace` lists frames outermost first and ends with the exception
type and message:

```text
Traceback (most recent call last):
  File "/app/server.py", line 42, in handler
ValueError: bad input
```

### Exception chains

An exception raised with `raise ... from` has a `__cause__`, and one raised while
another is being handled has a `__context__`, unless `__suppress_context__` hides
it, as `raise ... from None` does. The probe records the exception printed
directly before the reported one, with its type, message and the innermost 8
frames of its traceback. User space prints it before the reported exception, as
`traceback.format_exception` does:

```text
Traceback (most recent call last):
  File "/app/storage.py", line 12, in load
KeyError: 'user_id'

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/app/server.py", line 42, in handler
StorageError: lookup failed
```

The chain is read when the reported exception is raised. `__cause__` is set
before `_PyErr_SetObject` runs; `__context__` is the exception the thread is
handling, which `_PyErr_SetObject` sets after probe entry. An exception that was
never raised prints without a traceback, as in CPython.

| Payload part | Budget |
|---|---|
| Reported exception | type, 256-byte message, 24 frames |
| Chained exception, at most 1 | type, 128-byte message, 8 frames |
| Record payload | at most 968 bytes, 672 before chains |

Each request keeps three candidates in a 512-entry map allocated when Python
exception capture is enabled. The map values use about 1.5 MiB in total.

### Known limits

- A chain deeper than two exceptions ends at the second, without a marker.
- Nested exception groups are not expanded into separate tracebacks.
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
