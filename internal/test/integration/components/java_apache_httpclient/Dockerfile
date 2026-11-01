ARG JAVA_APACHE_RUNTIME_IMAGE=gradle:9.8.2-jdk21-noble@sha256:accd9bab093a3331697ede5aa9cecbb57d43217327e93d3cae989f1d28b49c0c
FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS proxy
WORKDIR /proxy
COPY internal/test/integration/components/java_httpclient_traceparent/proxy.go .
RUN CGO_ENABLED=0 go build -o proxy proxy.go && ./proxy certificate

FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS downstream
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/test/integration/components/java_apache_httpclient/downstream/main.go ./main.go
RUN CGO_ENABLED=0 go build -o /downstream main.go

FROM gradle:9.8.2-jdk21-noble@sha256:accd9bab093a3331697ede5aa9cecbb57d43217327e93d3cae989f1d28b49c0c AS build
ARG JAVA_APACHE_HTTPCLIENT_VERSION=4.5.14
WORKDIR /fixture
COPY internal/test/integration/components/java_apache_httpclient/Main.java ./
COPY internal/test/integration/components/java_apache_httpclient/build.gradle.kts ./
COPY --from=proxy /proxy/proxy.crt /proxy/proxy.key /proxy/proxy ./
COPY --from=downstream /downstream ./
RUN gradle compileJava runtimeLibraries "-PapacheHttpClientVersion=${JAVA_APACHE_HTTPCLIENT_VERSION}" --no-daemon && \
    keytool -importcert -noprompt -alias proxy -file proxy.crt \
      -keystore trust.p12 -storetype PKCS12 -storepass changeit
FROM ${JAVA_APACHE_RUNTIME_IMAGE}
WORKDIR /fixture
COPY --from=build /fixture /fixture
ENTRYPOINT ["java", "-Djavax.net.ssl.trustStore=/fixture/trust.p12", "-Djavax.net.ssl.trustStorePassword=changeit", "-cp", "build/classes/java/main:build/libs/*", "Main"]
