# Mise migration experiment

This change is a first feasibility slice, not a decision to replace Make. The
following common Go developer commands now run directly through Mise and do not
invoke Make:

| Mise task | Current behavior |
| --- | --- |
| `mise run format-go` | Runs the pinned `golangci-lint fmt`. |
| `mise run lint-go` | Runs Porto vanity-import validation, dependency-policy lint (verbose in CI), the CollectT analyzer, the BPF preemption-guard check, and `golangci-lint run ./... --timeout=6m`. |
| `mise run test-go` | Creates `TEST_OUTPUT` (default `./testoutput`), resolves `ENVTEST_K8S_VERSION` (default `1.30.0`) with the pinned `setup-envtest`, then runs the existing short, race-enabled all-package tests and coverage profile. |
| `mise run compile` | Builds the main `obi` binary with the same platform, version/revision linker flags, and command/file overrides as `make compile`. |

The corresponding Make targets remain intact as compatibility paths. The
current GitHub workflows have not been migrated wholesale; the existing Go
lint workflow already invokes `mise run lint-go`, while other workflow jobs
continue to use Make where required.

## Known gaps before considering a full replacement

- **Incremental eBPF generation:** `make generate` consumes the dependency
  files emitted by `bpf2go` (`*_bpfel.go.d` / `*_bpfeb.go.d`) to regenerate
  only affected packages. The current Mise tasks do not reproduce Make's
  dependency graph, architecture validation, missing-output detection, or
  per-package incremental behavior. Compile and tests still assume generated
  bindings exist; a clean checkout or changed BPF inputs may require
  `make generate` or `make docker-generate` first.
- **CI/workflow callers:** many workflows still invoke Make for setup,
  sharded tests, schema validation, integration suites, release, and artifact
  generation. Migrating these requires checking each job's containers,
  permissions, matrix variables, and expected artifacts rather than replacing
  commands mechanically.
- **Nested Makefiles/build fragments:** `bpf/tests/Makefile`,
  `internal/test/vm/Makefile`, the three `internal/test/integration/components/old_grpc/**/Makefile`
  files, `pkg/internal/java/agent/Makefile.jni`, and
  `pkg/internal/transform/route/harvest/dotnet/testdata/Makefile` have separate
  responsibilities and are not covered by this slice.
- **Integration and specialized tests:** integration, Kubernetes, OATS, VM,
  privileged, verifier, and Node.js tests use dedicated Make orchestration,
  environment setup, or nested build systems. They remain Make-only here.
- **Release and packaging:** release builds, checksums, notices, Java/Python
  packaging, schema publishing, and container image tasks are not represented
  by these Mise tasks.
- **Other root targets:** Go module maintenance and checks, license-header
  checks, upstream semantic-convention fetching, schema generation/validation,
  offset and protobuf generation, and Java verification still need an explicit
  Mise plan if the goal is to remove the root Makefile entirely.
- **Broader Make behavior:** task-variable compatibility is limited to the
  overrides documented by each task's equivalent Make target. Other targets,
  prerequisites such as hooks/semconv fetching, and Make's overall build graph
  have not been migrated or compared in this step.

Before removing Make, decide whether these gaps should be ported, intentionally
kept as Make sub-builds, or excluded from a Mise-based developer workflow; then
validate the chosen workflow against CI and clean-checkout builds.
