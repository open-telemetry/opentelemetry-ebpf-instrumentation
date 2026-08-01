# Reproducer for OBI issue #2706: HTTP/2 tunneled over a yamux-style transport.
# Pure stdlib — no external dependencies.
FROM python:3.14@sha256:61346539f7b26521a230e72c11da5ebd872924745074b19736e7d65ba748c366

COPY internal/test/integration/components/yamux/main.py /main.py

ENTRYPOINT ["python", "-u", "/main.py"]
