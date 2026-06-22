FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:548d93f8a18a1acbe6cc127bc4f47281430d34a9e35c18afa80a8d6741c2adc3 AS builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/dotnetserver .

RUN dotnet dev-certs https
RUN dotnet build


# Create final image from minimal + built binary
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:ddcf70ad1ab963a4fcd41fbd722a6b660e404e87567cfbd46fd2809c21b02088

WORKDIR /
COPY --from=builder /build/bin/Debug/net7.0/* .
COPY --from=builder /root/.dotnet/corefx/cryptography/x509stores/my/* /root/.dotnet/corefx/cryptography/x509stores/my/
ENV ASPNETCORE_URLS="https://0.0.0.0:7033;http://0.0.0.0:5266"

EXPOSE 7033
EXPOSE 5266

# Run the .net app
CMD [ "/dotnetserver"]
