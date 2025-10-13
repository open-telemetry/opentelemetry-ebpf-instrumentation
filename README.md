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

To get started with OBI, refer to the [OpenTelemetry doc](https://opentelemetry.io/docs/zero-code/).

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)

## License

OpenTelemetry eBPF Instrumentation is licensed under the terms of the Apache Software License version 2.0.
See the [license file](./LICENSE) for more details.
