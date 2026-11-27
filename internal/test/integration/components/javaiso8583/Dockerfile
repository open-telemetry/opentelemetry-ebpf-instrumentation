FROM maven:3.9-eclipse-temurin-25@sha256:93b8a14ea2f412782e4e842651273b4d903e35cc496284f178fbbe2d67d00976 AS builder

WORKDIR /build

COPY internal/test/integration/components/javaiso8583/pom.xml /build/pom.xml
COPY internal/test/integration/components/javaiso8583/src /build/src

RUN mvn -B --no-transfer-progress package dependency:copy-dependencies -DoutputDirectory=target/lib

FROM eclipse-temurin:25-jre@sha256:4ed132f6832e9804b123e89a849a7b4502756ae64a4ee08ebab939d9d5d0a9fa

WORKDIR /app

COPY --from=builder /build/target/lib /app/lib
COPY --from=builder /build/target/javaiso8583.jar /app/javaiso8583.jar

ENTRYPOINT ["java", "-cp", "/app/javaiso8583.jar:/app/lib/*", "IsoSwitch"]
