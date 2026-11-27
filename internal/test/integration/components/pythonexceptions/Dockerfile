ARG PYTHON_IMAGE=python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS go

FROM ${PYTHON_IMAGE}

COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/opt/exception-python/bin:/usr/local/go/bin:${PATH}" GOTOOLCHAIN=local

ARG PYTHON_VERSION=3.12.13
ARG PYTHON_EXCEPTION_BUILD=shared
COPY internal/test/integration/components/pythonexceptions/build-runtime.sh /tmp/build-runtime.sh
RUN PYTHON_VERSION=${PYTHON_VERSION} PYTHON_EXCEPTION_BUILD=${PYTHON_EXCEPTION_BUILD} sh /tmp/build-runtime.sh

COPY internal/test/integration/components/pythonexceptions/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt
WORKDIR /src
