FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:dc8430e6024d454edadad1e160e1973be3cabbb7125998ef190d9e5c6adf7dbb AS builder
WORKDIR /build
COPY internal/test/integration/components/grpc_relay/dotnet .
RUN dotnet publish -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:9b5222b0ff8e9eb991a7c1a64b25f0f771d21ccc05dfa1c834f5668ffd9cd73f
WORKDIR /app
COPY --from=builder /out .
ENTRYPOINT ["dotnet", "dotnetrelay.dll"]
