# Dockerfile that will build a container that runs python with FastAPI and paho-mqtt on port 8080
FROM python:3.14@sha256:4b827abf32c14b7df9a0dc5199c2f0bc46e2c9862cd5d77eddae8a2cd8460f60
EXPOSE 8080
RUN pip install fastapi uvicorn paho-mqtt
COPY internal/test/integration/components/pythonmqtt /main
WORKDIR /main
CMD ["python", "pythonmqtt.py"]

