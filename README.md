# OpenTelemetry eBPF Instrumentation

This repository provides eBPF instrumentation based on the OpenTelemetry standard.
It provides a lightweight and efficient way to collect telemetry data using eBPF for user-space applications.

**O**penTelemetry e-**B**PF **I**nstrumentation is commonly referred to as OBI.

:construction: This project is currently work in progress.

## How to start developing

Requirements:

* Docker
* GNU Make

1. First, generate all the eBPF Go bindings via `make docker-generate`. You need to re-run this make task
   each time you add or modify a C file under the [`bpf/`](./bpf) folder.
2. To run linter, unit tests: `make fmt verify`.
3. To run integration tests, run either:

```
make integration-test
make integration-test-k8s
make oats-test
```

, or all the above tasks. Each integration test target can take up to 50 minutes to complete, but you can
use standard `go` command-line tooling to individually run each integration test suite under
the [internal/test/integration](./internal/test/integration) and [internal/test/integration/k8s](./internal/test/integration/k8s) folder.

## Zero-code Instrumentation

Below are quick reference instructions for getting OBI up and running with binary downloads or container images. For comprehensive setup, configuration, and troubleshooting guidance, refer to the [OpenTelemetry zero-code instrumentation documentation](https://opentelemetry.io/docs/zero-code/), which is the authoritative source of truth.

## Installation

### Binary Download

OBI provides pre-built binaries for Linux (amd64 and arm64). Download the latest release from the [releases page](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases).

Each release includes:

- `obi-<version>-linux-amd64.tar.gz` - Linux AMD64/x86_64 archive
- `obi-<version>-linux-arm64.tar.gz` - Linux ARM64 archive
- `SHA256SUMS` - Checksums for verification

#### Download and Verify

```bash
# Set your desired version (find latest at https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases)
VERSION=1.0.0

# Determine your architecture
# For Intel/AMD 64-bit: amd64
# For ARM 64-bit: arm64
ARCH=amd64  # Change to arm64 for ARM systems

# Download the archive for your architecture
wget https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v${VERSION}/obi-v${VERSION}-linux-${ARCH}.tar.gz

# Download checksums
wget https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v${VERSION}/SHA256SUMS

# Verify the archive
sha256sum -c SHA256SUMS --ignore-missing

# Extract the archive
tar -xzf obi-v${VERSION}-linux-${ARCH}.tar.gz

# The archive contains:
# - ebpf-instrument: Main OBI binary
# - k8s-cache: Kubernetes cache binary
# - obi-java-agent.jar: Java agent
# - LICENSE: Project license
# - NOTICE: Legal notices
# - NOTICES/: Third-party licenses and attributions
```

#### Install to System

After extracting the archive, you can install the binaries to a location in your PATH so they can be used from any directory.

The OBI binary uses a default-deny approach for Java instrumentation, requiring the Java agent to be located in the same directory as the OBI executable. This ensures the agent is always available when OBI runs.

The following example installs to `/usr/local/bin`, which is a standard location on most Linux distributions. You can install to any other directory in your PATH:

```bash
# Move binaries to a directory in your PATH
sudo cp ebpf-instrument /usr/local/bin/
sudo cp k8s-cache /usr/local/bin/

# The Java agent MUST be in the same directory as the OBI binary
sudo cp obi-java-agent.jar /usr/local/bin/

# Verify installation
ebpf-instrument --version
```

### Container Images

OBI is also available as container images:

```bash
# Set your desired version (or use 'latest' for the most recent release)
VERSION=latest  # or VERSION=1.0.0 for a specific version

# Pull the image
docker pull docker.io/otel/ebpf-instrument:${VERSION}

# Run OBI in a container
# Note: OBI requires elevated privileges (--privileged) to instrument processes
# See https://opentelemetry.io/docs/zero-code/obi/setup/docker/ for more details
docker run --privileged docker.io/otel/ebpf-instrument:${VERSION}
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)

## License

OpenTelemetry eBPF Instrumentation is licensed under the terms of the Apache Software License version 2.0.
See the [license file](./LICENSE) for more details.
