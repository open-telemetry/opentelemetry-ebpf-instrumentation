# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Build the locally-vendored libstapsdt fork (arm64 + x86_64).
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS libstapsdt-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libelf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY internal/test/integration/components/libstapsdt-arm64/ /libstapsdt/
RUN make -C /libstapsdt all && make -C /libstapsdt install && ldconfig

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip libelf1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so /usr/lib/libstapsdt.so
COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so.0 /usr/lib/libstapsdt.so.0
RUN ldconfig

# python-stapsdt is pure ctypes; install via pip --break-system-packages so we
# don't need a venv inside this single-purpose image.
RUN printf 'stapsdt==0.1.1 --hash=sha256:fabc2ca82a7c7f7307bd5326a1a1cace720aa6e1682a53afe09f6cb20218e636\n' > /tmp/requirements.txt \
    && pip3 install --break-system-packages --require-hashes --no-deps -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY internal/test/integration/components/custom_span_python/app.py /app.py
EXPOSE 8392
ENTRYPOINT ["python3", "-u", "/app.py"]
