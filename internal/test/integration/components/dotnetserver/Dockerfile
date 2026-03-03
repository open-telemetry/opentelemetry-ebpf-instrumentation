FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:e362a8dbcd691522456da26a5198b8f3ca1d7641c95624fadc5e3e82678bd08a AS builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/dotnetserver .

RUN dotnet dev-certs https
RUN dotnet build


# Create final image from minimal + built binary
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:aec87aa74ddf129da573fa69f42f229a23c953a1c6fdecedea1aa6b1fe147d76

WORKDIR /
COPY --from=builder /build/bin/Debug/net7.0/* .
COPY --from=builder /root/.dotnet/corefx/cryptography/x509stores/my/* /root/.dotnet/corefx/cryptography/x509stores/my/
ENV ASPNETCORE_URLS="https://0.0.0.0:7033;http://0.0.0.0:5266"

EXPOSE 7033
EXPOSE 5266

# Run the .net app
CMD [ "/dotnetserver"]
