# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:3.12@sha256:a5bbd10dc5f2d6e965e101eef58f2f15cc3be5802cad7a12897aa443839c4943
EXPOSE 8080
RUN pip install fastapi uvicorn redis
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]