// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGetReadsOBIExtensionRoot(t *testing.T) {
	root := map[string]any{
		"extensions": map[string]any{
			"obi": map[string]any{
				"capture": map[string]any{
					"enabled": true,
				},
			},
		},
	}

	got, ok := get(root, "obi", "capture", "enabled")
	if !ok {
		t.Fatal("expected nested OBI extension value")
	}
	if got != true {
		t.Fatalf("unexpected value: %v", got)
	}
}

func TestPayloadExtractionMembershipMismatch(t *testing.T) {
	cur := map[string]any{
		"ebpf": map[string]any{
			"payload_extraction": map[string]any{
				"http": map[string]any{
					"graphql": map[string]any{
						"enabled": true,
					},
				},
			},
		},
	}
	ex := map[string]any{
		"extensions": map[string]any{
			"obi": map[string]any{
				"capture": map[string]any{
					"instrumentation": map[string]any{
						"http": map[string]any{
							"payload_extraction": map[string]any{
								"enabled": []any{"aws"},
							},
						},
					},
				},
			},
		},
	}

	err := mustMapPayloadExtractionMembership(cur, ex, "graphql")
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if !strings.Contains(err.Error(), "payload extraction mismatch for graphql") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLanguageDetectionSkipsCannotBecomeCaptureExclusions(t *testing.T) {
	cur, ex := loadCurrentAndExample(t)

	extensions := ex["extensions"].(map[string]any)
	obiExtension := extensions["obi"].(map[string]any)
	capture := obiExtension["capture"].(map[string]any)
	rules := capture["rules"].([]any)
	capture["rules"] = append(rules, map[string]any{
		"action": "exclude",
		"name":   "system-services",
		"match": map[string]any{
			"process": map[string]any{
				"exe_path_glob": []any{"/usr/sbin/*"},
			},
		},
	})

	err := mustKeepLanguageDetectionSkipsOutOfCaptureRules(cur, ex)
	if err == nil {
		t.Fatal("expected language-detection skip exclusion to fail")
	}
	if !strings.Contains(err.Error(), "must not be a capture exclusion") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyDefaultsCurrentExample(t *testing.T) {
	cur, ex := loadCurrentAndExample(t)

	failures, mappedChecks := verifyDefaults(cur, ex)
	if len(failures) > 0 {
		t.Fatalf("expected current defaults to match v2 example, got %d failures: %v", len(failures), failures)
	}
	if mappedChecks != len(parityChecks())+24 {
		t.Fatalf("unexpected mapped check count: %d", mappedChecks)
	}
}

func TestVerifyDefaultsDetectsMappedDefaultMismatch(t *testing.T) {
	cur, ex := loadCurrentAndExample(t)
	setPath(t, ex, []string{"extensions", "obi", "capture", "engine", "batching", "batch_length"}, 10101)

	failures, _ := verifyDefaults(cur, ex)
	if len(failures) == 0 {
		t.Fatal("expected verification failure")
	}

	for _, failure := range failures {
		if strings.Contains(failure.Error(), "batch_length") {
			return
		}
	}
	t.Fatalf("expected batch_length failure, got: %v", failures)
}

func loadCurrentAndExample(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()

	cur, err := currentDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	ex, err := readYAML(filepath.Join("..", "..", defaultV2DefaultPath))
	if err != nil {
		t.Fatal(err)
	}

	return cur, ex
}

func setPath(t *testing.T, root map[string]any, path []string, value any) {
	t.Helper()

	cur := root
	for _, item := range path[:len(path)-1] {
		next, ok := cur[item].(map[string]any)
		if !ok {
			t.Fatalf("path segment %q is not a map", item)
		}
		cur = next
	}
	cur[path[len(path)-1]] = value
}
