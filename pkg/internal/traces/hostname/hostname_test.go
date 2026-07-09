// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package hostname

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fullName     = "myhost.mdydomain.net"
	fullName2    = "changedHost.mdydomain.net"
	shortName    = "myhost"
	shortName2   = "changedHost"
	internalName = "myhost.localdomain"
)

// Fake functions for testing

func workingFull(_ string) (string, error)   { return fullName, nil }
func failingFull(_ string) (string, error)   { return "", errors.New("catapun") }
func workingShort() (string, error)          { return shortName, nil }
func failingShort() (string, error)          { return "", errors.New("patapam") }
func localhostFull(_ string) (string, error) { return "localhost", nil }
func localhostShort() (string, error)        { return "localhost", nil }
func internalFull() (string, error)          { return fullName, nil }
func internal() (string, error)              { return internalName, nil }

// Actual tests

func TestHostnameResolver_Query(t *testing.T) {
	resolver := fallbackResolver{full: workingFull, internal: internal, short: workingShort}

	full, err := resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, fullName, full)
}

func TestHostnameResolver_FullFails(t *testing.T) {
	// Given a Hostname Resolver whose full name can't be resolved
	resolver := fallbackResolver{full: failingFull, internal: failingShort, short: workingShort}

	// When the names are queried
	full, err := resolver.Query()
	// The short name is fallen back as full name
	require.NoError(t, err)
	assert.Equal(t, shortName, full)
}

func TestHostnameResolver_FullFailsFallingBackInInternal(t *testing.T) {
	// Given a Hostname Resolver whose full name can't be resolved
	resolver := fallbackResolver{full: failingFull, internal: internal, short: workingShort}

	// When the names are queried
	full, err := resolver.Query()
	// The internal name is fallen back as full name
	require.NoError(t, err)
	assert.Equal(t, internalName, full)
}

func TestHostnameResolver_FullIsLocalhost(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name string
	}{
		{
			name: "localhost",
		},
		{
			name: "ip6-localhost",
		},
		{
			name: "ipv6-localhost",
		},
		{
			name: "ip6-loopback",
		},
		{
			name: "ipv6-loopback",
		},
	}
	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			// Given a Hostname Resolver that resolves "localhost" as full hostname
			fullResolver := func(_ string) (string, error) { return testCase.name, nil }
			resolver := fallbackResolver{full: fullResolver, short: workingShort, internal: internalFull}

			// When the names are queried
			full, err := resolver.Query()
			// The internal kernel name is fallen back as full name
			require.NoError(t, err)
			assert.Equal(t, fullName, full)

			// And if the full name stop working
			resolver.full = failingFull

			// The stored full kernel hostname is returned anyway
			full, err = resolver.Query()
			require.NoError(t, err)
			assert.Equal(t, fullName, full)
		})
	}
}

func TestHostnameResolver_FullAndInternalAreLocalhost(t *testing.T) {
	// Given a Hostname Resolver that resolves "localhost" as full hostname
	resolver := fallbackResolver{full: localhostFull, short: workingShort, internal: localhostShort}

	// When the names are queried
	full, err := resolver.Query()
	// The short name is fallen back as full name
	require.NoError(t, err)
	assert.Equal(t, shortName, full)

	// And if the full name stop working
	resolver.full = failingFull

	// The short hostname is returned anyway
	full, err = resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, shortName, full)

	// And when the internal full name starts working
	resolver.internal = internal

	// The stored full kernel hostname is returned
	full, err = resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, internalName, full)

	// And when the full hostname starts working
	resolver.full = workingFull

	// The full hostname is returned
	full, err = resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, fullName, full)
}

func TestDNSResolver(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("", true)

	// resolves host names to some non-null hostnames
	full, err := resolver.Query()
	require.NoError(t, err)
	assert.NotEmpty(t, full)
}

func TestDNSResolver_Override(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("my-hostname.host.com", true)

	// resolves host names to the overridden hostnames
	full, err := resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, "my-hostname.host.com", full)
}

func TestDNSResolver_OverrideLocalhost(t *testing.T) {
	// invoking a New Hostname Resolver overridden with a non-recommended host name
	resolver := CreateResolver("localhost", true)

	// anyway resolves host names to the overridden hostname
	full, err := resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, "localhost", full)
}

func TestInternalResolver(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("", false)

	// resolves host names to some non-null hostnames
	full, err := resolver.Query()
	require.NoError(t, err)
	assert.NotEmpty(t, full)
}

func TestInternalResolver_Override(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("my-hostname.host.com", false)

	// resolves host names to the overridden hostnames
	full, err := resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, "my-hostname.host.com", full)
}

func TestInternalResolver_OverrideLocalhost(t *testing.T) {
	// invoking a New Hostname Resolver overridden with a non-recommended host name
	resolver := CreateResolver("localhost", false)

	// anyway resolves host names to the overridden hostname
	full, err := resolver.Query()
	require.NoError(t, err)
	assert.Equal(t, "localhost", full)
}
