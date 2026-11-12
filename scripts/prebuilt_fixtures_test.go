// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	integrationComposeDir = filepath.Join("..", "internal", "test", "integration")
	composeDefaultValue   = regexp.MustCompile(`\$\{[A-Za-z0-9_]+:?-([^}]*)\}`)
)

type fixtureService struct {
	Image string `yaml:"image"`
	Build any    `yaml:"build"`
}

// Shards skip building any service whose tag is prebuilt, so a prebuilt tag that another compose
// file builds from a different definition would silently run the wrong fixture there
func TestPrebuiltFixtureTagsHaveOneBuildDefinition(t *testing.T) {
	output, err := exec.Command("/bin/bash", "./discover-integration-images.sh", "--prebuild-compose-files").Output()
	if err != nil {
		t.Fatalf("listing the prebuilt compose files: %v", err)
	}

	prebuilt := map[string]any{}
	origin := map[string]string{}
	for file := range strings.FieldsSeq(string(output)) {
		for name, service := range composeFixtureServices(t, filepath.Join(integrationComposeDir, file)) {
			if service.Build == nil || slices.Contains(strings.Split(name, "-"), "obi") {
				continue
			}
			if service.Image == "" || strings.Contains(service.Image, "$") {
				t.Errorf("%s: service %s needs a fixed image tag to be prebuilt, got %q", file, name, service.Image)
				continue
			}
			prebuilt[service.Image] = normalizedBuild(service.Build)
			origin[service.Image] = file
		}
	}
	if len(prebuilt) == 0 {
		t.Fatal("no prebuilt fixture images found")
	}

	composeFiles, err := filepath.Glob(filepath.Join(integrationComposeDir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range composeFiles {
		for name, service := range composeFixtureServices(t, path) {
			image := composeDefaultValue.ReplaceAllString(service.Image, "$1")
			definition, ok := prebuilt[image]
			if !ok || service.Build == nil {
				continue
			}
			if !reflect.DeepEqual(definition, normalizedBuild(service.Build)) {
				t.Errorf("%s: service %s builds the prebuilt tag %s differently than %s; give it its own tag",
					filepath.Base(path), name, image, origin[image])
			}
		}
	}
}

func composeFixtureServices(t *testing.T, path string) map[string]fixtureService {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Services map[string]fixtureService `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return document.Services
}

func normalizedBuild(build any) any {
	definition, ok := build.(map[string]any)
	if !ok {
		definition = map[string]any{"context": build}
	}

	normalized := map[string]any{}
	for key, value := range definition {
		if path, ok := value.(string); ok && (key == "context" || key == "dockerfile") {
			value = filepath.Clean(path)
		}
		normalized[key] = value
	}
	return normalized
}
