# HTTP/2 client and server that put many streams in one buffer. Standard library
# only: an HTTP/2 library would send each stream on its own.
FROM python:3.15@sha256:3c24e0b3ef4c5e2409f918894ccd5e05756eea2015ae6ddd289179b20a049f9b

WORKDIR /app
COPY internal/test/integration/components/h2mux/ /app/

CMD ["python", "-u", "/app/server.py"]
