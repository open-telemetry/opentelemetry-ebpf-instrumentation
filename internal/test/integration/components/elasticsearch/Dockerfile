# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:3.12@sha256:01f36278bcca9fb4a5bdda7edc85be44218190a9371f642d8f852f36ad9fa23d
EXPOSE 8080
RUN apt update
RUN pip install fastapi uvicorn requests 
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
