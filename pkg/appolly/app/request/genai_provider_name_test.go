// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAICompatibleProviderName(t *testing.T) {
	// A gateway OBI has a member for is reported as configured.
	for _, configured := range []string{"litellm", "vllm", "localai", "openrouter", "openai", "anthropic"} {
		assert.Equal(t, configured, openAICompatibleProviderName(configured))
	}

	// Anything else is free-form configuration the enum has no member for, so
	// it reports as custom rather than emitting a value outside the contract.
	for _, configured := range []string{"", "together", "fireworks", "LiteLLM", "acme-proxy"} {
		assert.Equal(t, "custom", openAICompatibleProviderName(configured))
	}
}

// The Go value space and the declared enum are two copies of the same list, so
// a provider added to one and not the other would emit a value live-check
// rejects. This fails the moment they disagree.
func TestGenAIProviderNamesMatchRegistry(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "schemas", "obi", "groups", "gen_ai", "registry.yaml")
	body, err := os.ReadFile(path)
	require.NoError(t, err)

	// The provider enum is the first `members:` block in the file; stop at the
	// next attribute so later enums do not leak in.
	section := string(body)
	start := regexp.MustCompile(`(?m)^\s+- id: gen_ai\.provider\.name$`).FindStringIndex(section)
	require.NotNil(t, start, "gen_ai.provider.name not declared in %s", path)
	section = section[start[1]:]
	if end := regexp.MustCompile(`(?m)^\s+- id: gen_ai\.operation\.name$`).FindStringIndex(section); end != nil {
		section = section[:end[0]]
	}

	declared := map[string]struct{}{}
	for _, m := range regexp.MustCompile(`(?m)^\s+value: "([^"]+)"$`).FindAllStringSubmatch(section, -1) {
		declared[m[1]] = struct{}{}
	}
	require.NotEmpty(t, declared, "no enum members parsed from %s", path)

	assert.Equal(t, declared, genAIProviderNames)
}
