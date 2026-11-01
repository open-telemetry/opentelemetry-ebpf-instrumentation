ARG JAVA_HTTPCLIENT_RUNTIME_IMAGE=gradle:9.8.2-jdk21-noble@sha256:accd9bab093a3331697ede5aa9cecbb57d43217327e93d3cae989f1d28b49c0c
FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS proxy
WORKDIR /proxy
COPY internal/test/integration/components/java_httpclient_traceparent/proxy.go .
RUN CGO_ENABLED=0 go build -o proxy proxy.go && ./proxy certificate
FROM gradle:9.8.2-jdk21-noble@sha256:accd9bab093a3331697ede5aa9cecbb57d43217327e93d3cae989f1d28b49c0c AS build

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
