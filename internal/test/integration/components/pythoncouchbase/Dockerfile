# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:3.14@sha256:61346539f7b26521a230e72c11da5ebd872924745074b19736e7d65ba748c366
EXPOSE 8080
RUN pip install fastapi uvicorn couchbase
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
