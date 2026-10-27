// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	kindMetric = "metric"
	kindSpan   = "span"

	levelRequired              = "required"
	levelConditionallyRequired = "conditionally_required"
	levelRecommended           = "recommended"
	levelOptIn                 = "opt_in"

	resolveTimeout = 5 * time.Minute
)

var requirementLevels = []string{levelRequired, levelConditionallyRequired, levelRecommended, levelOptIn}

type resolvedAttribute struct {
	Key              string          `json:"key"`
	Type             json.RawMessage `json:"type"`
	RequirementLevel json.RawMessage `json:"requirement_level"`
}

type resolvedMetric struct {
	Name       string              `json:"name"`
	Attributes []resolvedAttribute `json:"attributes"`
}

type resolvedSpan struct {
	Type       string              `json:"type"`
	Attributes []resolvedAttribute `json:"attributes"`
}

type resolvedRegistry struct {
	Registry struct {
		Metrics []resolvedMetric `json:"metrics"`
		Spans   []resolvedSpan   `json:"spans"`
	} `json:"registry"`
}

type DeclaredAttribute struct {
	Key              string `json:"key"`
	RequirementLevel string `json:"requirement_level"`
	Template         bool   `json:"template,omitempty"`
}

// observedIn reports whether a key of the attribute was seen. A template
// attribute is emitted as `<key>.<suffix>` keys rather than under its own key.
func (a DeclaredAttribute) observedIn(seen map[string]struct{}) bool {
	if _, ok := seen[a.Key]; ok {
		return true
	}
	if !a.Template {
		return false
	}
	for key := range seen {
		if strings.HasPrefix(key, a.Key+".") {
			return true
		}
	}
	return false
}

type Signal struct {
	Name       string              `json:"name"`
	Kind       string              `json:"kind"`
	Attributes []DeclaredAttribute `json:"attributes"`
}

// requirementLevel reduces a resolved requirement level, either a bare word or
// a single-key object carrying the condition, to its word. Weaver defaults an
// unset level to recommended.
func requirementLevel(raw json.RawMessage) string {
	var word string
	if err := json.Unmarshal(raw, &word); err == nil && word != "" {
		return word
	}
	var conditional map[string]json.RawMessage
	if err := json.Unmarshal(raw, &conditional); err == nil {
		for level := range conditional {
			return level
		}
	}
	return levelRecommended
}

func declaredAttributes(attrs []resolvedAttribute) []DeclaredAttribute {
	out := make([]DeclaredAttribute, 0, len(attrs))
	for _, a := range attrs {
		var typ string
		_ = json.Unmarshal(a.Type, &typ)
		out = append(out, DeclaredAttribute{
			Key:              a.Key,
			RequirementLevel: requirementLevel(a.RequirementLevel),
			Template:         strings.HasPrefix(typ, "template["),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// parseSignals reads the metric and span definitions of the v2 resolved
// registry. Live-check resolves without --include-unreferenced, so every one is
// a signal OBI emits: its own, or an upstream definition it imports.
func parseSignals(resolved []byte) ([]Signal, error) {
	var reg resolvedRegistry
	if err := json.Unmarshal(resolved, &reg); err != nil {
		return nil, fmt.Errorf("parsing resolved registry: %w", err)
	}

	var signals []Signal
	for _, m := range reg.Registry.Metrics {
		signals = append(signals, Signal{Name: m.Name, Kind: kindMetric, Attributes: declaredAttributes(m.Attributes)})
	}
	for _, s := range reg.Registry.Spans {
		signals = append(signals, Signal{Name: s.Type, Kind: kindSpan, Attributes: declaredAttributes(s.Attributes)})
	}
	if len(signals) == 0 {
		return nil, errors.New("resolved registry declares no metric or span")
	}
	sort.Slice(signals, func(i, j int) bool { return signals[i].Name < signals[j].Name })
	return signals, nil
}

// resolveSchema runs `weaver registry resolve --v2`. Weaver can exit non-zero on
// a diagnostic while still writing the complete resolved registry, so the
// output is judged by parseSignals rather than by the exit code.
func resolveSchema(ociBin, image, schemaPath string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, ociBin, "run", "--rm",
		"-v", schemaPath+":/obi-registry:ro",
		"-w", "/obi-registry",
		image, "registry", "resolve",
		"--registry", "/obi-registry",
		"--v2",
		"--format", "json")
	out, err := cmd.Output()
	if len(out) == 0 {
		return nil, fmt.Errorf("running weaver registry resolve: %w", err)
	}
	return out, nil
}
