# Build JNI native library using Go image (has gcc, no apt install needed)
FROM golang:1.25.8@sha256:f55a6ec7f24aedc1ed66e2641fdc52de01f2d24d6e49d1fa38582c07dd5f601d AS jni-builder
COPY --from=gradle:9.3.1-jdk21-noble@sha256:f3784cc59d7fbab1e0ddb09c4cd082f13e16d3fb8c50b7922b7aeae8e9507da5 /opt/java/openjdk/include /opt/java/include
WORKDIR /build
COPY pkg/internal/java/agent/src/main/c/ src/main/c/
COPY pkg/internal/java/agent/Makefile.jni Makefile.jni
RUN make -f Makefile.jni CC=gcc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c

FROM gradle:9.3.1-jdk21-noble@sha256:f3784cc59d7fbab1e0ddb09c4cd082f13e16d3fb8c50b7922b7aeae8e9507da5 AS builder

WORKDIR /build

# Copy build files
COPY pkg/internal/java .
# Pre-built native library from jni-builder stage
COPY --from=jni-builder /build/target/classes/libobijni.so agent/target/classes/libobijni.so

# Build the project (skip native lib compilation, already done above)
RUN gradle build -x buildNativeLib --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar