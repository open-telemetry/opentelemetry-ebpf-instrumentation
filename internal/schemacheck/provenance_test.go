// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	registryDir = "../../schemas/obi"

	resolveTimeout = 2 * time.Minute
)

// provenance names where a resolved definition comes from: a dependency's
// schema url as its source, or no source for a definition of this registry.
type provenance struct {
	Source string `json:"source"`
	Path   string `json:"path"`
}

func (p provenance) local() bool { return p.Source == "" }

type resolvedAttribute struct {
	Key              string          `json:"key"`
	Type             json.RawMessage `json:"type"`
	Brief            string          `json:"brief"`
	Stability        string          `json:"stability"`
	RequirementLevel json.RawMessage `json:"requirement_level"`
	Deprecated       *struct {
		RenamedTo string `json:"renamed_to"`
	} `json:"deprecated"`
	Provenance  provenance `json:"provenance"`
	Annotations struct {
		OBI struct {
			UpstreamDeviation string `json:"upstream_deviation"`
		} `json:"obi"`
	} `json:"annotations"`
}

// resolvedSignal is a span, metric or attribute group of the resolved registry,
// identified by its type, name or id respectively.
type resolvedSignal struct {
	Type        string              `json:"type"`
	Name        json.RawMessage     `json:"name"`
	ID          string              `json:"id"`
	Provenance  provenance          `json:"provenance"`
	Attributes  []resolvedAttribute `json:"attributes"`
	Annotations struct {
		OBI struct {
			Upstream        upstreamLink      `json:"upstream"`
			UpstreamReason  string            `json:"upstream_reason"`
			UpstreamOmits   map[string]string `json:"upstream_omits"`
			UpstreamRelaxes map[string]string `json:"upstream_relaxes"`
			UpstreamExtras  map[string]string `json:"upstream_extras"`
		} `json:"obi"`
	} `json:"annotations"`
}

type resolveOutput struct {
	Registry struct {
		Attributes      []resolvedAttribute `json:"attributes"`
		Spans           []resolvedSignal    `json:"spans"`
		Metrics         []resolvedSignal    `json:"metrics"`
		AttributeGroups []resolvedSignal    `json:"attribute_groups"`
	} `json:"registry"`
	Refinements struct {
		Spans []resolvedSignal `json:"spans"`
	} `json:"refinements"`
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

// requireWeaver checks that the Mise-managed Weaver CLI is available. If it is
// unavailable, the check skips locally and fails in CI.
func requireWeaver(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("provenance checks are skipped in -short mode; run `mise run test:schema`")
	}
	if _, err := exec.LookPath("weaver"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("weaver is required for the provenance check in CI: %v", err)
		}
		t.Skipf("weaver is not installed (%v); run `mise install`", err)
	}
	// Without the pinned upstream registry weaver cannot resolve, and the
	// failure says nothing about the registry under test. Skip as the drift
	// tests do, but fail closed in CI where the fetch is part of the target.
	if _, err := os.Stat(upstreamDeps); os.IsNotExist(err) {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is required for the provenance check in CI; run `mise run fetch-upstream-semconv`", upstreamDeps)
		}
		t.Skipf("%s is not populated; run `mise run fetch-upstream-semconv`", upstreamDeps)
	}
}

// weaverCommand runs the Mise-managed `weaver` CLI from the registry directory.
func weaverCommand(ctx context.Context, t *testing.T, args ...string) *exec.Cmd {
	t.Helper()

	registryAbs, err := filepath.Abs(registryDir)
	require.NoError(t, err)

	cmd := exec.CommandContext(ctx, "weaver", args...)
	cmd.Dir = registryAbs
	return cmd
}

// resolveRegistry runs `weaver registry resolve --v2` and returns the resolved registry.
func resolveRegistry(t *testing.T) resolveOutput {
	t.Helper()
	return resolveRegistryAt(t, "")
}

func resolveRegistryAt(t *testing.T, registry string) resolveOutput {
	t.Helper()
	requireWeaver(t)

	ctx, cancel := context.WithTimeout(t.Context(), resolveTimeout)
	defer cancel()

	registryAbs, err := filepath.Abs(filepath.Join(registryDir, registry))
	require.NoError(t, err)
	cmd := weaverCommand(ctx, t,
		"registry", "resolve", "--registry", registryAbs, "--v2", "--format", "json")

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
				"the provenance check cannot be skipped once weaver is installed",
			err, stderr)
	}
	require.NotEmpty(t, res.Registry.Metrics, "weaver resolve returned no metrics")
	return res
}

// TestOBIMetricOverridesResolveToLocalNarrowedDefinition verifies that every
// metric OBI declares under an upstream metric's name resolves to OBI's own
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
