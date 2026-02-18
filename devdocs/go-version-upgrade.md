# Upgrading the Go Version

When upgrading to a newer Go version, one or two PRs are needed:

- First, ensure obi-generator golang image is bumped in
  [generator.Dockerfile](../generator.Dockerfile).
  - Either wait for your PR merge to main, or if on a source branch (not a fork),
    run the [Publish OBI Docker Generator Image](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/workflows/generator-image.yml)
    action. Ensure `Use workflow from` is correct (`main` or your source branch), leave tag override empty.
  - **Ensure the workflow completes successfully**, otherwise checks will fail in
    your next PR. This workflow will only work from main and source brances.

- Then, once the new obi-generator image is available ([check here](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkgs/container/obi-generator)):
  - Update the [Makefile](../Makefile) `GEN_IMG` to the new `obi-generator` tag.

  - Update the [Dockerfile](../Dockerfile) `TAG` to the new `obi-generator` tag.

  - In `go.mod` files only: search/replace `go i.j.k` with `go x.y.z`, where
    `i.j.k` is your current version and `x.y.z` is your new version.

  - [Find the index digest](https://hub.docker.com/_/golang/tags) for your new
    multi-platform golang image, and search/replace the entire `FROM golang:...`
    line. This should cover the Dockerfiles.

  - Search entire codebase for any remaining references for old version `i.j.k`
    and fix as needed.

  - Raise final PR to bump to `x.y.z`.
