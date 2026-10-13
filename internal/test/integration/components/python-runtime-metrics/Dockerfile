# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

ARG PYTHON_RUNTIME_METRICS_IMAGE=python:3.15.0@sha256:3c24e0b3ef4c5e2409f918894ccd5e05756eea2015ae6ddd289179b20a049f9b

FROM ${PYTHON_RUNTIME_METRICS_IMAGE}

COPY internal/test/integration/components/python-runtime-metrics/server.py /server.py
COPY internal/test/integration/components/python-runtime-metrics/automatic.py /automatic.py
COPY internal/test/integration/components/python-runtime-metrics/controlled.py /controlled.py

EXPOSE 8080

CMD ["python3", "/server.py"]
