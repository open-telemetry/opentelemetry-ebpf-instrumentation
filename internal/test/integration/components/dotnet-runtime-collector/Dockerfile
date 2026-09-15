ARG DOTNET_RUNTIME_IMAGE=mcr.microsoft.com/dotnet/runtime:8.0-bookworm-slim@sha256:9d94ecf60a21c6e7a784cf0761fbd4a8391646617a0ff2f39621443d580cc2c3
FROM mcr.microsoft.com/dotnet/sdk:9.0@sha256:f190d2dd9eef2899c91ac323caa0bd2b39334a5400ba93013e5199da39dad940 AS build

WORKDIR /src
COPY internal/test/integration/components/dotnet-runtime-metrics/*.csproj workload/
COPY internal/test/integration/components/dotnet-runtime-collector/*.csproj collector/
RUN dotnet restore workload && dotnet restore collector
COPY internal/test/integration/components/dotnet-runtime-metrics/*.cs workload/
COPY internal/test/integration/components/dotnet-runtime-collector/*.cs collector/
RUN dotnet publish workload --no-restore -o /app/workload && \
    dotnet publish collector --no-restore -o /app/collector

FROM ${DOTNET_RUNTIME_IMAGE}
COPY --from=build /app /app
ENV DOTNET_ROLL_FORWARD=Major
ENTRYPOINT ["dotnet", "/app/collector/dotnet-runtime-collector.dll", "/app/workload/dotnet-runtime-metrics.dll", "/output"]
