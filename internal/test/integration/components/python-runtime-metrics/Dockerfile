# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

ARG PYTHON_RUNTIME_METRICS_IMAGE=python:3.12.7@sha256:8d97a0ab83113f8984517f14492f57186d943db7815682cab9d820c9c0a8c998

FROM ${PYTHON_RUNTIME_METRICS_IMAGE}

COPY internal/test/integration/components/python-runtime-metrics/server.py /server.py
COPY internal/test/integration/components/python-runtime-metrics/automatic.py /automatic.py
COPY internal/test/integration/components/python-runtime-metrics/controlled.py /controlled.py

EXPOSE 8080

CMD ["python3", "/server.py"]
