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
For the environments and artifact platforms OBI currently documents as supported, see [SUPPORT_MATRIX.md](./SUPPORT_MATRIX.md).

## Telemetry Schema

OBI's emission contract is defined as a [Weaver](https://github.com/open-telemetry/weaver)-compatible schema registry under [schemas/obi/](./schemas/obi/).

It extends the upstream [OpenTelemetry semantic conventions](https://github.com/open-telemetry/semantic-conventions) registry with the metrics, spans, and attributes OBI emits that are not covered upstream.

## How to start developing

Requirements:

* Docker
* GNU Make

1. First, generate all the eBPF Go bindings via `make docker-generate`. You need to re-run this make task
   each time you add or modify a C file under the [`bpf/`](./bpf) folder.
2. To run linter, unit tests: `make fmt verify`.
3. To run integration tests, run either:

```bash
make integration-test
make integration-test-k8s
make oats-test
```

, or all the above tasks. Each integration test target can take up to 50 minutes to complete, but you can
use standard `go` command-line tooling to individually run each integration test suite under
the [internal/test/integration](./internal/test/integration) and [internal/test/integration/k8s](./internal/test/integration/k8s) folder.

## Zero-code Instrumentation

Below are quick reference instructions for getting OBI up and running with binary downloads or container images. For comprehensive setup, configuration, and troubleshooting guidance, refer to the [OpenTelemetry zero-code instrumentation documentation](https://opentelemetry.io/docs/zero-code/), which is the authoritative source of truth.

For release artifact verification and installation details, see:

- [Run OBI as a standalone process](https://opentelemetry.io/docs/zero-code/obi/setup/standalone/)
- [Run OBI as a Docker container](https://opentelemetry.io/docs/zero-code/obi/setup/docker/)

## Installation

### Binary Download

OBI provides pre-built binaries for Linux (amd64 and arm64). Download the latest release from the [releases page](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases).

Each release includes:

- `obi-v<version>-linux-amd64.tar.gz` - Linux AMD64/x86_64 archive
- `obi-v<version>-linux-arm64.tar.gz` - Linux ARM64 archive
- `obi-v<version>-source-generated.tar.gz` - generated source archive
- `obi-v<version>-linux-amd64.cyclonedx.json` - CycloneDX SBOM for the AMD64 archive
- `obi-v<version>-linux-arm64.cyclonedx.json` - CycloneDX SBOM for the ARM64 archive
- `obi-v<version>-source-generated.cyclonedx.json` - CycloneDX SBOM for the source-generated archive
- `obi-java-agent-v<version>.cyclonedx.json` - CycloneDX SBOM for the embedded Java agent and its Java dependencies
- `SHA256SUMS` - Checksums for verification of the release archives and SBOM assets
- `<asset>.bundle.json` - Sigstore bundle for each signed archive, SBOM, and `SHA256SUMS`

#### Download and Verify

Install [Cosign](https://docs.sigstore.dev/cosign/installation/) if you do not already have it.
OBI release blobs are signed with GitHub Actions OIDC. The identity regexp
below matches the same repository-level identity used for container image
verification.

```bash
# Set your desired version (find latest at https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases)
export VERSION=1.0.0

# Determine your architecture
# For Intel/AMD 64-bit: amd64
# For ARM 64-bit: arm64
export ARCH=amd64  # Change to arm64 for ARM systems

export RELEASE_TAG=v${VERSION}
export BASE_URL="https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/${RELEASE_TAG}"
export ARTIFACT="obi-${RELEASE_TAG}-linux-${ARCH}.tar.gz"
export BUNDLE="${ARTIFACT}.bundle.json"
export CHECKSUMS=SHA256SUMS
export CHECKSUMS_BUNDLE="${CHECKSUMS}.bundle.json"
export CERTIFICATE_IDENTITY_REGEXP="https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/"
export CERTIFICATE_OIDC_ISSUER="https://token.actions.githubusercontent.com"
```

Download the archive, checksum manifest, and their Sigstore bundles:

```bash
wget "${BASE_URL}/${ARTIFACT}"
wget "${BASE_URL}/${BUNDLE}"
wget "${BASE_URL}/${CHECKSUMS}"
wget "${BASE_URL}/${CHECKSUMS_BUNDLE}"
```

Verify the signatures before using the downloaded files:

```bash
cosign verify-blob "${ARTIFACT}" \
  --bundle "${BUNDLE}" \
  --certificate-identity-regexp "${CERTIFICATE_IDENTITY_REGEXP}" \
  --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}"

cosign verify-blob "${CHECKSUMS}" \
  --bundle "${CHECKSUMS_BUNDLE}" \
  --certificate-identity-regexp "${CERTIFICATE_IDENTITY_REGEXP}" \
  --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}"
```

Successful Cosign verification confirms that the local file matches the signed
payload, the signing certificate identity matches this repository's GitHub
Actions identity, the certificate was issued by GitHub Actions OIDC, and the
Sigstore bundle includes the transparency log material needed for offline
verification.

Then verify the downloaded files against the signed checksum manifest:

```bash
sha256sum -c "${CHECKSUMS}" --ignore-missing
```

Successful verification prints an `OK` result for each file you downloaded:

```text
obi-v${VERSION}-linux-${ARCH}.tar.gz: OK
```

If Cosign or checksum verification fails, stop and do not run or compile the
artifact. Confirm the version, artifact name, bundle name, and architecture,
then re-download the artifact and bundle from the same release. If verification
still fails, use the GitHub Security tab's "Report a vulnerability" flow for
this repository with the release version and failed verification output. Do not
open a public issue with potentially sensitive details.

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

The release SBOMs describe the contents of the published archives and embedded
components in [CycloneDX JSON format](https://cyclonedx.org/). They can be
consumed by dependency analysis and vulnerability scanning tools without
extracting or executing the binaries.

Download the SBOMs you want to inspect:

```bash
# SBOM for the binary archive you downloaded
wget "${BASE_URL}/obi-${RELEASE_TAG}-linux-${ARCH}.cyclonedx.json"

# SBOM for the embedded Java agent and its Java dependencies
wget "${BASE_URL}/obi-java-agent-${RELEASE_TAG}.cyclonedx.json"

# Optional: verify the downloaded SBOM files against SHA256SUMS too
sha256sum -c "${CHECKSUMS}" --ignore-missing
```

Release SBOMs also have matching `.bundle.json` files and can be verified with
the same `cosign verify-blob` command pattern shown above.

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
export VERSION=v0.7.0

# (Optional) Verify the signature of the container image
cosign verify --certificate-identity-regexp 'https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' otel/ebpf-instrument:${VERSION}

# (Optional) Verify the same release from GHCR
cosign verify --certificate-identity-regexp 'https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' ghcr.io/open-telemetry/opentelemetry-ebpf-instrumentation/ebpf-instrument:${VERSION}

# Pull the image
docker pull otel/ebpf-instrument:${VERSION}

# Or pull the same image from GHCR
docker pull ghcr.io/open-telemetry/opentelemetry-ebpf-instrumentation/ebpf-instrument:${VERSION}

# Run OBI in a container
# Note: OBI requires elevated privileges (--privileged) to instrument processes
# See https://opentelemetry.io/docs/zero-code/obi/setup/docker/ for more details
docker run --privileged otel/ebpf-instrument:${VERSION}
```

Successful `cosign verify` output states that the claims were validated and
returns the signed image digest. If verification fails, confirm that the image
tag exists in the registry you queried and that you are using the GitHub OIDC
issuer and identity regexp shown above.

## Examples

- [OTel Collector Receiver Example](./examples/otel-collector/README.md)
- [NGINX Multi-Route And Proxy Example](./examples/nginx/README.md)

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) and [OpenTelemetry eBPF Instrumentation Generative AI Policy](AI-POLICY.md).

## License

OpenTelemetry eBPF Instrumentation is licensed under the terms of the Apache Software License version 2.0.
See the [license file](./LICENSE) for more details.
