// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// GetBuildTags returns a slice of the build tags used to compile the binary.
func GetBuildTags() []string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}

	for _, setting := range info.Settings {
		if setting.Key == "-tags" {
			// Tags are comma-separated in the build info
			return strings.Split(setting.Value, ",")
		}
	}

	return nil
}

func setIntegrity(t *testing.T, path, text string) {
	err := os.WriteFile(path, []byte(text), 0o644)
	require.NoError(t, err)
}

func setNotReadable(t *testing.T, path string) {
	err := os.Chmod(path, 0o00)
	require.NoError(t, err)
}

func TestLockdownParsing(t *testing.T) {
	noFile, err := os.CreateTemp(t.TempDir(), "not_existent_fake_lockdown")
	require.NoError(t, err)
	notPath, err := filepath.Abs(noFile.Name())
	require.NoError(t, err)
	noFile.Close()
	os.Remove(noFile.Name())

	// Setup for testing file that doesn't exist
	lockdownPath = notPath
	assert.Equal(t, KernelLockdownNone, KernelLockdownMode())

	tempFile, err := os.CreateTemp(t.TempDir(), "fake_lockdown")
	require.NoError(t, err)
	path, err := filepath.Abs(tempFile.Name())
	require.NoError(t, err)
	tempFile.Close()

	defer os.Remove(tempFile.Name())
	// Setup for testing
	lockdownPath = path

	setIntegrity(t, path, "none [integrity] confidentiality\n")
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())

	setIntegrity(t, path, "[none] integrity confidentiality\n")
	assert.Equal(t, KernelLockdownNone, KernelLockdownMode())

	setIntegrity(t, path, "none integrity [confidentiality]\n")
	assert.Equal(t, KernelLockdownConfidentiality, KernelLockdownMode())

	setIntegrity(t, path, "whatever\n")
	assert.Equal(t, KernelLockdownOther, KernelLockdownMode())

	setIntegrity(t, path, "")
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())

	if slices.Contains(GetBuildTags(), "privileged_tests") {
		// This test doesn't pass when run as sudo
		t.Skip("Skipping this test because privileged_tests tag is set")
	}

	setIntegrity(t, path, "[none] integrity confidentiality\n")
	setNotReadable(t, path)
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())
}

// TestIsH2CPrefacePseudoRequest pins that the HTTP/2 connection preface
// ("PRI * HTTP/2.0"), which Go's h2c path surfaces as a literal request, is
// recognized (and thus dropped by ReadBPFTraceAsSpan) while real requests
// are not.
func TestIsH2CPrefacePseudoRequest(t *testing.T) {
	preface := request.Span{Type: request.EventTypeHTTP, Method: "PRI", Path: "*"}
	assert.True(t, isH2CPrefacePseudoRequest(&preface))

	clientPreface := request.Span{Type: request.EventTypeHTTPClient, Method: "PRI", Path: "*"}
	assert.True(t, isH2CPrefacePseudoRequest(&clientPreface))

	for _, span := range []request.Span{
		{Type: request.EventTypeHTTP, Method: "GET", Path: "*"},
		{Type: request.EventTypeHTTP, Method: "PRI", Path: "/pri"},
		{Type: request.EventTypeHTTP, Method: "GET", Path: "/users"},
		{Type: request.EventTypeKafkaClient, Method: "PRI", Path: "*"},
	} {
		assert.False(t, isH2CPrefacePseudoRequest(&span), "span %+v must not be dropped", span)
	}
}
