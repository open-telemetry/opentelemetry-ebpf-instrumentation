# Dockerfile for a single-threaded keep-alive HTTP server that also acts as a client
FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae
EXPOSE 8080

WORKDIR /

COPY internal/test/integration/components/latchsrv .

CMD ["python", "-u", "app.py"]
