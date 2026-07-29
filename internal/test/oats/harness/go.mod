module go.opentelemetry.io/obi/internal/test/oats/harness

go 1.25.11

require (
	github.com/onsi/ginkgo/v2 v2.28.1
	github.com/onsi/gomega v1.41.0
	go.opentelemetry.io/obi v0.0.0-00010101000000-000000000000
)

// The oats harness reuses the shared weaver-validation logic
// (internal/test/weavercheck) from the root obi module, so the Docker,
// Kubernetes, and OATS suites enforce identical semantic-convention rules.
//
// This is an INTENTIONAL module coupling with known costs beyond the imported
// package itself (which only uses stdlib + testify): requiring the root
// module puts its full requirement set into MVS, raising the minimum versions
// of shared dependencies (collector pdata, the OTel SDK, gRPC, …) for the
// harness and every OATS group module — so an unrelated root dependency bump
// can ripple into these go.sum files. And because `replace` directives are
// not transitive, every OATS group module must repeat this same
// require/replace pair.
//
// The alternatives all have worse trade-offs today: a nested weavercheck
// module would need an unpublishable v0.0.0 require in the ROOT go.mod
// (breaking downstream consumers of go.opentelemetry.io/obi unless the
// nested module is tagged on every release), and moving the integration
// tests out of the root module is a much larger layout change. The broader
// module-layout cleanup is tracked as follow-up work.
replace go.opentelemetry.io/obi => ../../../..

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20260115054156-294ebfa9ad83 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
