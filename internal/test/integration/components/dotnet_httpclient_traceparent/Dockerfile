FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS downstream-build
WORKDIR /downstream
COPY internal/test/integration/components/dotnet_httpclient_traceparent/downstream.go .
RUN CGO_ENABLED=0 go build -o downstream downstream.go

# Its own target, so compose builds the downstream instead of pulling an image tag
FROM scratch AS downstream
COPY --from=downstream-build /downstream/downstream /downstream
ENTRYPOINT ["/downstream"]

FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:ebecce75fb42c4c14db108f88054d20a93b0b9e6dfbacad56c8f744c342cf9ef AS build
WORKDIR /build
COPY internal/test/integration/components/dotnet_httpclient_traceparent/Program.cs \
     internal/test/integration/components/dotnet_httpclient_traceparent/dotnethttpclient.csproj ./
RUN dotnet publish -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:8.0@sha256:93154e00cb227f2fad30724455ecd1e77f46afc9a0273590af652ac220664e54
WORKDIR /app
COPY --from=build /out .
ENTRYPOINT ["dotnet", "dotnethttpclient.dll"]
