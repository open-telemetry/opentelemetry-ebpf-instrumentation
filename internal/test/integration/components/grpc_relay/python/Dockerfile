FROM python:3.15@sha256:3c24e0b3ef4c5e2409f918894ccd5e05756eea2015ae6ddd289179b20a049f9b

COPY internal/test/integration/components/grpc_relay/python/requirements.txt /requirements.txt
RUN pip install --require-hashes -r /requirements.txt

WORKDIR /app

COPY internal/test/integration/components/grpc_relay/relay.proto .
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. relay.proto

COPY internal/test/integration/components/grpc_relay/python/server.py .

CMD ["python", "server.py"]
