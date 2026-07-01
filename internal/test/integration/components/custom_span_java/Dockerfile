# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Stage 1: build libstapsdt from the locally-vendored arm64-capable fork.
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS libstapsdt-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libelf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY internal/test/integration/components/libstapsdt-arm64/ /libstapsdt/
RUN make -C /libstapsdt all && make -C /libstapsdt install && ldconfig

# Stage 2: compile App.class + libjstapsdt.so (JNI bridge to libstapsdt).
FROM eclipse-temurin:21-jdk@sha256:762d16be48b976c97801d198e5085b1f6facb13718a1e8fb67cb25d0b25337e1 AS java-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libelf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so /usr/lib/libstapsdt.so
COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so.0 /usr/lib/libstapsdt.so.0
COPY --from=libstapsdt-builder /usr/include/libstapsdt.h /usr/include/libstapsdt.h
RUN ldconfig

WORKDIR /src
COPY internal/test/integration/components/custom_span_java/App.java ./
COPY internal/test/integration/components/custom_span_java/Stapsdt.java ./
COPY internal/test/integration/components/custom_span_java/jstapsdt.c ./
RUN javac App.java Stapsdt.java \
    && gcc -shared -fPIC -O2 -o /usr/lib/libjstapsdt.so \
        -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
        jstapsdt.c -lstapsdt

FROM eclipse-temurin:21-jdk@sha256:762d16be48b976c97801d198e5085b1f6facb13718a1e8fb67cb25d0b25337e1

RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so /usr/lib/libstapsdt.so
COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so.0 /usr/lib/libstapsdt.so.0
COPY --from=java-builder /usr/lib/libjstapsdt.so /usr/lib/libjstapsdt.so
RUN ldconfig

WORKDIR /app
COPY --from=java-builder /src/App.class /src/Stapsdt.class /app/
EXPOSE 8395
ENTRYPOINT ["java", "-cp", "/app", "App"]
