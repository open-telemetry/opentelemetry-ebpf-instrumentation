ARG JAVA_HTTPCLIENT_RUNTIME_IMAGE=gradle:9.8.2-jdk21-noble@sha256:1278203f5f52e4781e6d7096250375a4d54ab599f26e5ba44e672b4bdbd793f7
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS proxy
WORKDIR /proxy
COPY internal/test/integration/components/java_httpclient_traceparent/proxy.go .
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod CGO_ENABLED=0 go build -o proxy proxy.go && ./proxy certificate
FROM gradle:9.8.2-jdk21-noble@sha256:1278203f5f52e4781e6d7096250375a4d54ab599f26e5ba44e672b4bdbd793f7 AS build

WORKDIR /fixture
ADD --checksum=sha256:5b35ccc6c275fd477a06db01923813e13d99c1a52a20b0ea8ed6576eae177c7d https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.21.0/opentelemetry-javaagent-2.21.0.jar /fixture/opentelemetry-javaagent.jar
COPY internal/test/integration/components/java_httpclient_traceparent/Main.java .
COPY --from=proxy /proxy/proxy.crt /proxy/proxy.key /proxy/proxy ./
RUN javac --release 11 Main.java && \
    keytool -importcert -noprompt -alias proxy -file proxy.crt \
      -keystore trust.p12 -storetype PKCS12 -storepass changeit
FROM ${JAVA_HTTPCLIENT_RUNTIME_IMAGE}
WORKDIR /fixture
COPY --from=build /fixture /fixture
ENTRYPOINT ["java", "-Djavax.net.ssl.trustStore=/fixture/trust.p12", "-Djavax.net.ssl.trustStorePassword=changeit", "Main"]
