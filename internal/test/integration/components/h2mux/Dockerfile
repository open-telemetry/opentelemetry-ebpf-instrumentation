# HTTP/2 client and server that put many streams in one buffer. Standard library
# only: an HTTP/2 library would send each stream on its own.
FROM python:3.14@sha256:61346539f7b26521a230e72c11da5ebd872924745074b19736e7d65ba748c366

WORKDIR /app
COPY internal/test/integration/components/h2mux/ /app/

CMD ["python", "-u", "/app/server.py"]
