FROM python:3.14.3-slim@sha256:6a27522252aef8432841f224d9baaa6e9fce07b07584154fa0b9a96603af7456
WORKDIR /app
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt
COPY server.py .
ENV PORT=8080 BATCH=5
EXPOSE 8080
CMD ["python3", "server.py"]
