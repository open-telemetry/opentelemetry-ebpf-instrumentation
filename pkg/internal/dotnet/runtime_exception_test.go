// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func TestExceptionTypeLabels(t *testing.T) {
	var types exceptionTypes
	for i := range maximumExceptionTypes {
		name := "Failure" + strconv.Itoa(i)
		label, err := types.labelFor("Example." + name)
		require.NoError(t, err)
		require.Equal(t, name, label)
	}
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"OtherNamespace.Failure0", "Failure0"},
		{"Example.NewFailure", exceptionTypeOther},
		{strings.Repeat("x", maximumExceptionTypeBytes+1), exceptionTypeOther},
		{exceptionTypeOther, exceptionTypeOther},
	} {
		label, err := types.labelFor(tc.raw)
		require.NoError(t, err)
		require.Equal(t, tc.want, label)
	}
	require.Len(t, types.names, maximumExceptionTypes)
	for _, raw := range []string{"", "Example."} {
		_, err := types.labelFor(raw)
		require.ErrorContains(t, err, "empty name")
	}

	var fresh exceptionTypes
	label, err := fresh.labelFor(strings.Repeat("x", maximumExceptionTypeBytes+1))
	require.NoError(t, err)
	require.Equal(t, exceptionTypeOther, label)
	require.Empty(t, fresh.names)
	name := strings.Repeat("x", maximumExceptionTypeBytes)
	label, err = fresh.labelFor(name)
	require.NoError(t, err)
	require.Equal(t, name, label)
	require.Len(t, fresh.names, 1)
}

func TestIsCLRExceptionThrown(t *testing.T) {
	header := netTraceMetadataHeader{
		ProviderName: "Microsoft-Windows-DotNETRuntime", EventID: 80, Version: 1,
	}
	require.True(t, isCLRExceptionThrown(header))
	for _, other := range []netTraceMetadataHeader{
		{ProviderName: "System.Runtime", EventID: 80, Version: 1},
		{ProviderName: header.ProviderName, EventID: 81, Version: 1},
		{ProviderName: header.ProviderName, EventID: 80, Version: 2},
	} {
		require.False(t, isCLRExceptionThrown(other))
	}
}

func clrExceptionPayload(name string, pointerSize int32) []byte {
	var payload []byte
	for _, value := range []string{name, "test message"} {
		for _, unit := range utf16.Encode([]rune(value + "\x00")) {
			payload = binary.LittleEndian.AppendUint16(payload, unit)
		}
	}
	return append(payload, make([]byte, int(pointerSize)+4+2+2)...)
}

func TestDecodeCLRExceptionType(t *testing.T) {
	for _, pointerSize := range []int32{4, 8} {
		payload := clrExceptionPayload("Example.Outer+Inner", pointerSize)
		name, err := decodeCLRExceptionType(bytes.NewReader(payload), pointerSize)
		require.NoError(t, err)
		require.Equal(t, "Example.Outer+Inner", name)
		for size := range len(payload) {
			_, err := decodeCLRExceptionType(bytes.NewReader(payload[:size]), pointerSize)
			require.Error(t, err)
		}
		_, err = decodeCLRExceptionType(bytes.NewReader(append(payload, 0)), pointerSize)
		require.Error(t, err)
	}
	_, err := decodeCLRExceptionType(bytes.NewReader(nil), 3)
	require.Error(t, err)
	_, err = decodeCLRExceptionType(bytes.NewReader(clrExceptionPayload("", 8)), 8)
	require.ErrorContains(t, err, "ExceptionType")
}

func TestShortCLRExceptionType(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"System.InvalidOperationException", "InvalidOperationException"},
		{"Contoso.Failure`1[System.String]", "Failure`1"},
		{"Failure[System.String]", "Failure"},
		{"Failure", "Failure"},
		{"Contoso.Échec", "Échec"},
		{"Contoso.Outer+Inner", "Inner"},
		{"", ""},
		{"Contoso.", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.want, shortCLRExceptionType(tc.input))
		})
	}
}

func TestCLRExceptionRecordedTrace(t *testing.T) {
	trace, err := os.Open("testdata/exceptions-net8.nettrace")
	require.NoError(t, err)
	defer trace.Close()
	counts := map[string]uint64{}
	require.NoError(t, readRuntimeEvents(trace, 1, func(event netTraceRuntimeEvent) error {
		if event.exceptionType != "" {
			counts[shortCLRExceptionType(event.exceptionType)]++
		}
		return nil
	}))
	require.Equal(t, map[string]uint64{"Pr5Caught": 1, "Pr5Rethrown": 2, "Pr5ExplicitRethrow": 2, "Pr5Dispatch": 2, "Pr5Generic`1": 1, "Pr5Nested": 1, "Pr5Background": 1}, counts)
}
