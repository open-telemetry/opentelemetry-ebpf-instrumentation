FROM python:3.14.3-slim@sha256:6a27522252aef8432841f224d9baaa6e9fce07b07584154fa0b9a96603af7456

COPY internal/test/integration/components/peermetadata/app.py /peer-metadata/app.py

ENTRYPOINT ["python", "/peer-metadata/app.py"]
