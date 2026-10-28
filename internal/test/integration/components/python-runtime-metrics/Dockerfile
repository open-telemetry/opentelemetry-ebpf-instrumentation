# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

ARG PYTHON_RUNTIME_METRICS_IMAGE=python:3.15.2@sha256:d7a732b20de2f5d3cf977cbcf69aacf30dc928a37908ff9fdb7bb3503024c91a

FROM ${PYTHON_RUNTIME_METRICS_IMAGE}

COPY internal/test/integration/components/python-runtime-metrics/server.py /server.py
COPY internal/test/integration/components/python-runtime-metrics/automatic.py /automatic.py
COPY internal/test/integration/components/python-runtime-metrics/controlled.py /controlled.py

EXPOSE 8080

CMD ["python3", "/server.py"]
