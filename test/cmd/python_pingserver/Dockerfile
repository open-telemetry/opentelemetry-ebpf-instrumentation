# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:latest@sha256:855caf820856a90fa94a8064cb247a72fcec4f67ebd3ec7c84cc3970da8a6526
EXPOSE 8080
RUN pip install fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]