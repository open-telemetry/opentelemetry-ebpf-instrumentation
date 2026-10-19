# Reproducer for OBI issue #2706: HTTP/2 tunneled over a yamux-style transport.
# Pure stdlib — no external dependencies.
FROM python:3.15@sha256:3c24e0b3ef4c5e2409f918894ccd5e05756eea2015ae6ddd289179b20a049f9b

COPY internal/test/integration/components/yamux/main.py /main.py

ENTRYPOINT ["python", "-u", "/main.py"]
