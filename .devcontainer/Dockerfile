FROM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS go
FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

COPY --from=go /usr/local/go /usr/local/go

# Include the runtime dependencies needed by the IDE backends.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl docker-cli gcc git jq libc6-dev make procps sudo unzip \
    libfreetype6 libstdc++6 libxext6 libxi6 libxrender1 libxtst6 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid vscode --create-home --shell /bin/bash vscode \
    && echo 'vscode ALL=(root) NOPASSWD:ALL' > /etc/sudoers.d/vscode \
    && chmod 0440 /etc/sudoers.d/vscode

COPY --chmod=0755 setup-docker.sh /usr/local/bin/devcontainer-setup-docker

ENV PATH="/usr/local/go/bin:/home/vscode/go/bin:${PATH}" \
    GOPATH=/home/vscode/go \
    GOMODCACHE=/home/vscode/go/pkg/mod \
    GOCACHE=/home/vscode/.cache/go-build \
    DOCKER_HOST=unix:///var/run/docker.sock

USER vscode
CMD ["sleep", "infinity"]
