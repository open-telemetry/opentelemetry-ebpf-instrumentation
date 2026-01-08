# Dockerfile that will build a container that runs python with FastAPI and paho-mqtt on port 8080
FROM python:3.12@sha256:f3396041c12dac446a6b824cbb027ad9f65f6836fef93fc0187e0380ebf10fe3
EXPOSE 8080
RUN pip install fastapi uvicorn paho-mqtt
COPY internal/test/integration/components/pythonmqtt /main
WORKDIR /main
CMD ["python", "pythonmqtt.py"]

