# Dockerfile that will build a container that runs python with FastAPI and paho-mqtt on port 8080
FROM python:3.12@sha256:de96c54f25e2d69597a72bd3309d723110e59586845c5675c8cb83afb808af18
EXPOSE 8080
RUN pip install fastapi uvicorn paho-mqtt
COPY internal/test/integration/components/pythonmqtt /main
WORKDIR /main
CMD ["python", "pythonmqtt.py"]

