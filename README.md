# OpenTelemetry eBPF Instrumentation

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/open-telemetry/opentelemetry-ebpf-instrumentation)

This repository provides eBPF instrumentation based on the OpenTelemetry standard.
It provides a lightweight and efficient way to collect telemetry data using eBPF for user-space applications.

**O**penTelemetry e-**B**PF **I**nstrumentation is commonly referred to as OBI.

## Project Status

OBI is currently in Development. Users should expect breaking changes between minor releases while the project remains in `v0`.

If you are evaluating OBI for production use:

- pin to a specific semver release tag instead of relying on `latest`, which is a moving, non-stable tag
- review release notes before upgrading between minor versions
- expect configuration, behavior, supported environments, and emitted telemetry to change between `v0` minor releases
- avoid assuming telemetry continuity for dashboards, alerts, or downstream processors before OBI declares those surfaces stable

For the project's versioning and stability policy, see [VERSIONING.md](./VERSIONING.md).

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

- `obi-v<version>-linux-amd64.tar.gz` - Linux AMD64/x86_64 archive
- `obi-v<version>-linux-arm64.tar.gz` - Linux ARM64 archive
- `obi-v<version>-linux-amd64.cyclonedx.json` - CycloneDX SBOM for the AMD64 archive
- `obi-v<version>-linux-arm64.cyclonedx.json` - CycloneDX SBOM for the ARM64 archive
- `obi-v<version>-source-generated.cyclonedx.json` - CycloneDX SBOM for the source-generated archive
- `obi-java-agent-v<version>.cyclonedx.json` - CycloneDX SBOM for the embedded Java agent and its Java dependencies
- `SHA256SUMS` - Checksums for verification of the release archives and SBOM assets

#### Download and Verify

```bash
# Set your desired version (find latest at https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases)
export VERSION=1.0.0

# Determine your architecture
# For Intel/AMD 64-bit: amd64
# For ARM 64-bit: arm64
export ARCH=amd64  # Change to arm64 for ARM systems
```

Download the archive and checksum manifest:

```bash
# Download the archive for your architecture
wget https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v${VERSION}/obi-v${VERSION}-linux-${ARCH}.tar.gz

# Download checksums
wget https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v${VERSION}/SHA256SUMS
```

Verify the downloaded release assets:

```bash
# Verify the archive you downloaded
sha256sum -c SHA256SUMS --ignore-missing
```

Extract the archive:

```bash
tar -xzf obi-v${VERSION}-linux-${ARCH}.tar.gz

# The archive contains:
# - obi: Main OBI binary
# - k8s-cache: Kubernetes cache binary
# - LICENSE: Project license
# - NOTICE: Legal notices
# - NOTICES/: Third-party licenses and attributions
```

#### Optional: Download and Inspect SBOMs

CycloneDX SBOM files are optional metadata for supply-chain review and automation.
They are not required to install or run OBI.

Download the SBOMs you want to inspect:

```bash
# SBOM for the binary archive you downloaded
wget https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v${VERSION}/obi-v${VERSION}-linux-${ARCH}.cyclonedx.json

# SBOM for the embedded Java agent and its Java dependencies
wget https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v${VERSION}/obi-java-agent-v${VERSION}.cyclonedx.json

# Optional: verify the downloaded SBOM files against SHA256SUMS too
sha256sum -c SHA256SUMS --ignore-missing
```

Inspect the SBOM contents with common tools:

```bash
# List component names and versions from the archive SBOM
jq '.components[] | {name, version}' obi-v${VERSION}-linux-${ARCH}.cyclonedx.json

# Scan the SBOM with Grype
grype sbom:obi-v${VERSION}-linux-${ARCH}.cyclonedx.json

# Inspect the Java agent dependency graph
jq '.components[] | {name, version}' obi-java-agent-v${VERSION}.cyclonedx.json
```

#### Install to System

After extracting the archive, you can install the binaries to a location in your PATH so they can be used from any directory.

The Java agent is embedded in the `obi` binary, so no separate Java agent JAR installation is required.
At runtime, OBI extracts the embedded Java agent into the user cache directory (typically `$XDG_CACHE_HOME/obi/java` or `~/.cache/obi/java`) and reuses a checksum-named cached file across runs.

The following example installs to `/usr/local/bin`, which is a standard location on most Linux distributions. You can install to any other directory in your PATH:

```bash
# Move binaries to a directory in your PATH
sudo cp obi /usr/local/bin/
sudo cp k8s-cache /usr/local/bin/

# Verify installation
obi --version
```

### Container Images

OBI is also available as container images:

```bash
# Set your desired version.
export VERSION=1.0.0

# (Optional) Verify the signature of the container image
cosign verify --certificate-identity-regexp 'https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' otel/ebpf-instrument:${VERSION}

# Pull the image
docker pull otel/ebpf-instrument:${VERSION}

# Run OBI in a container
# Note: OBI requires elevated privileges (--privileged) to instrument processes
# See https://opentelemetry.io/docs/zero-code/obi/setup/docker/ for more details
docker run --privileged otel/ebpf-instrument:${VERSION}
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)

## License

OpenTelemetry eBPF Instrumentation is licensed under the terms of the Apache Software License version 2.0.
See the [license file](./LICENSE) for more details.
