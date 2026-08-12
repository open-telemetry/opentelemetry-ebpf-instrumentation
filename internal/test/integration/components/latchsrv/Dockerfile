# Dockerfile for a single-threaded keep-alive HTTP server that also acts as a client
FROM python:3.14.3-slim@sha256:6a27522252aef8432841f224d9baaa6e9fce07b07584154fa0b9a96603af7456
EXPOSE 8080

WORKDIR /

COPY internal/test/integration/components/latchsrv .

CMD ["python", "-u", "app.py"]
