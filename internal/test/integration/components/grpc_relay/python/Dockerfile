FROM python:3.14@sha256:61346539f7b26521a230e72c11da5ebd872924745074b19736e7d65ba748c366

COPY internal/test/integration/components/grpc_relay/python/requirements.txt /requirements.txt
RUN pip install --require-hashes -r /requirements.txt

WORKDIR /app

COPY internal/test/integration/components/grpc_relay/relay.proto .
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. relay.proto

COPY internal/test/integration/components/grpc_relay/python/server.py .

CMD ["python", "server.py"]
