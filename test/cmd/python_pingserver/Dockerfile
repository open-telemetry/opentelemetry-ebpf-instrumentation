# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:latest@sha256:0c745292b7b34dcdd6050527907d78c39363dc45ad6afc6d107c454b93cebca1
EXPOSE 8080
RUN pip install fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]