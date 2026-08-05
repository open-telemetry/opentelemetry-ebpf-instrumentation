// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestMisclassifiedHandlersAreCollectionScoped(t *testing.T) {
	var callsA atomic.Int32
	var callsB atomic.Int32
	collectionA := &EBPFEventContext{}
	collectionB := &EBPFEventContext{}
	unsetA := collectionA.SetMisclassifiedEventHandler(func(context.Context, MisclassifiedEvent) {
		callsA.Add(1)
	})
	defer unsetA()
	unsetB := collectionB.SetMisclassifiedEventHandler(func(context.Context, MisclassifiedEvent) {
		callsB.Add(1)
	})
	defer unsetB()

	runCtx := context.Background()
	parseA := NewEBPFParseContext(
		nil, nil, nil, WithMisclassifiedEventHandler(runCtx, collectionA.HandleMisclassifiedEvent),
	)
	parseB := NewEBPFParseContext(
		nil, nil, nil, WithMisclassifiedEventHandler(runCtx, collectionB.HandleMisclassifiedEvent),
	)
	event := MisclassifiedEvent{EventType: EventTypeKHTTP2}
	parseA.handleMisclassifiedEvent(event)
	require.Equal(t, int32(1), callsA.Load())
	require.Zero(t, callsB.Load())
	parseB.handleMisclassifiedEvent(event)
	require.Equal(t, int32(1), callsA.Load())
	require.Equal(t, int32(1), callsB.Load())

	unsetA()
	parseA.handleMisclassifiedEvent(event)
	parseB.handleMisclassifiedEvent(event)
	require.Equal(t, int32(1), callsA.Load(), "unsetting A does not route its event to B")
	require.Equal(t, int32(2), callsB.Load())
}

func TestUnsetMisclassifiedHandlerWaitsForInFlightCall(t *testing.T) {
	collection := &EBPFEventContext{}
	entered := make(chan struct{})
	release := make(chan struct{})
	unset := collection.SetMisclassifiedEventHandler(func(context.Context, MisclassifiedEvent) {
		close(entered)
		<-release
	})

	dispatched := make(chan struct{})
	go func() {
		collection.HandleMisclassifiedEvent(context.Background(), MisclassifiedEvent{})
		close(dispatched)
	}()
	<-entered

	unsetDone := make(chan struct{})
	go func() {
		unset()
		close(unsetDone)
	}()
	select {
	case <-unsetDone:
		t.Fatal("unregistration returned while a handler was still in flight")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	require.Eventually(t, func() bool {
		select {
		case <-unsetDone:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
	<-dispatched
}

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
