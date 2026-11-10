# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder

WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -o mock-server main.go

FROM alpine:3.20@sha256:77726ef6b3f2d775bfba713f16bdf0d8ee8f1abf1872ff356c83289254d7f1a6
COPY --from=builder /app/mock-server /mock-server
EXPOSE 8084
CMD ["/mock-server"]
