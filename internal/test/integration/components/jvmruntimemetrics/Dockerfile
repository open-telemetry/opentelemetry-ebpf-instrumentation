ARG JRE_IMAGE=eclipse-temurin:17.0.18_8-jre@sha256:ff692acf872589e72ca71b416b3e949ec19f35ebe8abb5365d2f31bce298e762

FROM eclipse-temurin:17@sha256:b624cb9175b71aaeb654dd9def666035332d5abf70318537c1a46e61564dbecd AS builder

WORKDIR /build
COPY internal/test/integration/components/jvmruntimemetrics/Main.java .
RUN javac --release 8 -d /classes Main.java

FROM ${JRE_IMAGE}

COPY --from=builder /classes /app
EXPOSE 8085
ENTRYPOINT ["java", "-Xms128m", "-Xmx128m", "-XX:+UseSerialGC", "-cp", "/app", "Main"]
