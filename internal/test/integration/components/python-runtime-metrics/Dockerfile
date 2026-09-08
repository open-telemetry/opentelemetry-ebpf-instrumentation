# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

ARG PYTHON_RUNTIME_METRICS_IMAGE=python:3.14.7@sha256:8edbf9e42c7fb168b9c523718ed907117e6d2e60f5889c0c499bbda3a787da53

FROM ${PYTHON_RUNTIME_METRICS_IMAGE}

COPY internal/test/integration/components/python-runtime-metrics/server.py /server.py
COPY internal/test/integration/components/python-runtime-metrics/automatic.py /automatic.py
COPY internal/test/integration/components/python-runtime-metrics/controlled.py /controlled.py

EXPOSE 8080

CMD ["python3", "/server.py"]
