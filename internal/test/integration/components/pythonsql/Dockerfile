# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:3.15@sha256:f17ec845ebdd4f3347431579e1c22eaeec82913f039f2a54b937c7ff870bacdb
EXPOSE 8080
RUN apt update
RUN apt install -y libpq-dev
COPY requirements.txt /requirements.txt
RUN pip install --require-hashes -r /requirements.txt
COPY main.py /main.py
COPY main_sync.py /main_sync.py
COPY server.crt /server.crt
COPY server.key /server.key
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
