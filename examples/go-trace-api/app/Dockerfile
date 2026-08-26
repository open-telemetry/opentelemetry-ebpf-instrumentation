FROM --platform=$BUILDPLATFORM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/go-trace-api .

FROM gcr.io/distroless/static@sha256:f2ea2709ac8db56323cbd7d014277f32cb572d9ea124b0076f7aafe5980678fe

COPY --from=builder /out/go-trace-api /go-trace-api

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/go-trace-api"]
