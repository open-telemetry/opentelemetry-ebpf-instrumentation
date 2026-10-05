// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	registryDir = "../../schemas/obi"

	resolveTimeout = 2 * time.Minute

	// Probing the runtime must not hang a test run when a daemon is wedged.
	runtimeProbeTimeout = 15 * time.Second
)

// provenance names where a resolved definition comes from: a dependency's
// schema url as its source, or no source for a definition of this registry.
type provenance struct {
	Source string `json:"source"`
	Path   string `json:"path"`
}

func (p provenance) local() bool { return p.Source == "" }

type resolvedAttribute struct {
	Key        string     `json:"key"`
	Provenance provenance `json:"provenance"`
}

// resolvedSignal is a span, metric or attribute group of the resolved registry,
// identified by its type, name or id respectively.
type resolvedSignal struct {
	Type       string              `json:"type"`
	Name       json.RawMessage     `json:"name"`
	ID         string              `json:"id"`
	Provenance provenance          `json:"provenance"`
	Attributes []resolvedAttribute `json:"attributes"`
}

type resolveOutput struct {
	Registry struct {
		Attributes      []resolvedAttribute `json:"attributes"`
		Spans           []resolvedSignal    `json:"spans"`
		Metrics         []resolvedSignal    `json:"metrics"`
		AttributeGroups []resolvedSignal    `json:"attribute_groups"`
	} `json:"registry"`
}

func (s resolvedSignal) metricName(t *testing.T) string {
	t.Helper()
	var name string
	require.NoError(t, json.Unmarshal(s.Name, &name))
	return name
}

// label names a span by its type, an attribute group by its id and a metric by
// its name.
func (s resolvedSignal) label(t *testing.T) string {
	t.Helper()
	if s.Type != "" {
		return s.Type
	}
	if s.ID != "" {
		return s.ID
	}
	return s.metricName(t)
}

var weaverImageRE = regexp.MustCompile(`(?m)^FROM\s+(otel/weaver:\S+)\s+AS\s+weaver`)

func weaverImage(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../dependencies.Dockerfile")
	require.NoError(t, err)
	m := weaverImageRE.FindSubmatch(body)
	require.Lenf(t, m, 2, "could not find the weaver image in dependencies.Dockerfile")
	return string(m[1])
}

// requireWeaverRuntime returns the container runtime that runs the pinned
// weaver image, the same one `make lint-schema` uses, rather than a `weaver`
// binary on PATH so the result matches the version OBI targets. If the runtime
// is unavailable it skips: these guarantees are only assertable when weaver can
// actually resolve the registry, and `make lint-schema` covers real resolution
// errors separately.
func requireWeaverRuntime(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("the check runs a container; skipped in -short mode. Run `make test-schema`")
	}
	ociBin := os.Getenv("OCI_BIN")
	if ociBin == "" {
		ociBin = "docker"
	}
	// The binary existing is not enough: Docker Desktop leaves its CLI on PATH
	// with the daemon stopped, which would fail the check for a reason that
	// says nothing about the registry.
	if err := runtimeUsable(t, ociBin); err != nil {
		// Skipping keeps `go test ./...` usable on a machine with no reachable
		// container runtime, but in CI that would silently void the guarantee,
		// so fail there instead.
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is required for the provenance check in CI: %v", ociBin, err)
		}
		t.Skipf("%s is not usable (%v); skipping provenance check", ociBin, err)
	}
	// Without the pinned upstream registry weaver cannot resolve, and the
	// failure says nothing about the registry under test. Skip as the drift
	// tests do, but fail closed in CI where the fetch is part of the target.
	if _, err := os.Stat(upstreamDeps); os.IsNotExist(err) {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is required for the provenance check in CI; run `make fetch-upstream-semconv`", upstreamDeps)
		}
		t.Skipf("%s is not populated; run `make fetch-upstream-semconv`", upstreamDeps)
	}
	return ociBin
}

// weaverCommand runs `weaver <args>` in the pinned image with the registry
// mounted read-only as its working directory.
func weaverCommand(ctx context.Context, t *testing.T, ociBin string, args ...string) *exec.Cmd {
	t.Helper()

	registryAbs, err := filepath.Abs(registryDir)
	require.NoError(t, err)

	runArgs := []string{
		"run", "--rm", "-i",
		"-v", registryAbs + ":/obi-registry:ro", "-w", "/obi-registry",
		weaverImage(t),
	}
	return exec.CommandContext(ctx, ociBin, append(runArgs, args...)...)
}

// resolveRegistry runs `weaver registry resolve --v2` through the pinned weaver
// image and returns the resolved registry.
func resolveRegistry(t *testing.T) resolveOutput {
	t.Helper()
	ociBin := requireWeaverRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), resolveTimeout)
	defer cancel()

	cmd := weaverCommand(ctx, t, ociBin,
		"registry", "resolve", "--registry", "/obi-registry", "--v2", "--format", "json")

	// weaver can exit non-zero when diagnostics exist (e.g. the expected
	// definition/2 UnstableFileFormat warnings), yet still writes the resolved
	// registry JSON to stdout. Parse stdout regardless of the exit code, and
	// treat the run as unavailable only when there is no JSON to parse.
	out, err := cmd.Output()

	var res resolveOutput
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		var stderr []byte
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			stderr = exitErr.Stderr
		}
		require.NoErrorf(t, jsonErr,
			"weaver resolve produced no parseable registry JSON (run error: %v)\n%s\n"+
				"the provenance check cannot be skipped once the runtime is present",
			err, stderr)
	}
	require.NotEmpty(t, res.Registry.Metrics, "weaver resolve returned no metrics")
	return res
}

// runtimeUsable reports whether the container runtime can actually run
// something, not merely whether its CLI is installed.
func runtimeUsable(t *testing.T, bin string) error {
	t.Helper()

	if _, err := exec.LookPath(bin); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(t.Context(), runtimeProbeTimeout)
	defer cancel()

	if out, err := exec.CommandContext(ctx, bin, "info").CombinedOutput(); err != nil {
		return fmt.Errorf("%s info: %w: %s", bin, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// TestOBIMetricOverridesResolveToLocalNarrowedDefinition verifies that every
// metric marked with annotations.obi.upstream_override resolves to OBI's own
// narrowed definition rather than the broader upstream one. Unreferenced
// upstream metrics drop from resolution, leaving exactly one metric per shared
// name: OBI's. This is what makes the coverage denominator reflect OBI's true
// OTLP contract.
func TestOBIMetricOverridesResolveToLocalNarrowedDefinition(t *testing.T) {
	overrides := overrideMetrics(t)
	require.NotEmpty(t, overrides)

	byName := map[string][]resolvedSignal{}
	for _, m := range resolveRegistry(t).Registry.Metrics {
		byName[m.metricName(t)] = append(byName[m.metricName(t)], m)
	}

	for name := range overrides {
		metrics := byName[name]
		require.Lenf(t, metrics, 1,
			"metric %q should resolve to exactly one definition without --include-unreferenced, got %d: %v",
			name, len(metrics), metrics)
		assert.Truef(t, metrics[0].Provenance.local(),
			"metric %q resolves to %v; expected OBI's narrowed local definition, not the upstream one",
			name, metrics[0].Provenance)
	}
}

// TestLocalAttributeDefinitionsWinOnEveryCarrier verifies that an attribute this
// registry defines, including an override of an upstream key such as
// `error.type`, resolves to OBI's definition on every span, metric and
// attribute group that carries it, rather than to the upstream definition of
// the same key.
func TestLocalAttributeDefinitionsWinOnEveryCarrier(t *testing.T) {
	defined := definedAttributes(registryFiles(t))
	require.Contains(t, defined, "error.type", "the error.type override is no longer defined locally")

	res := resolveRegistry(t)
	checked := 0
	for kind, signals := range map[string][]resolvedSignal{
		"span":            res.Registry.Spans,
		"metric":          res.Registry.Metrics,
		"attribute group": res.Registry.AttributeGroups,
	} {
		for _, s := range signals {
			if !s.Provenance.local() {
				continue
			}
			for _, a := range s.Attributes {
				if _, ok := defined[a.Key]; !ok {
					continue
				}
				checked++
				assert.Truef(t, a.Provenance.local(),
					"%s %s carries %q from %v instead of OBI's definition",
					kind, s.label(t), a.Key, a.Provenance)
			}
		}
	}
	require.Positive(t, checked, "no carrier of a locally defined attribute was resolved")
}
