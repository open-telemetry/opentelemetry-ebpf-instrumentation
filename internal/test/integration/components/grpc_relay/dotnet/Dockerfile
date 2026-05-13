FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:ebecce75fb42c4c14db108f88054d20a93b0b9e6dfbacad56c8f744c342cf9ef AS builder
WORKDIR /build
COPY internal/test/integration/components/grpc_relay/dotnet .
RUN dotnet publish -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:8.0@sha256:93154e00cb227f2fad30724455ecd1e77f46afc9a0273590af652ac220664e54
WORKDIR /app
COPY --from=builder /out .
ENTRYPOINT ["dotnet", "dotnetrelay.dll"]
