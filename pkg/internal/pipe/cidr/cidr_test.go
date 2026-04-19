// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cidr

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

type testRecord struct {
	pipe.CommonAttrs
}

func defs(cidrs ...string) Definitions {
	d := make(Definitions, len(cidrs))
	for i, c := range cidrs {
		d[i] = Definition{CIDR: c}
	}
	return d
}

func TestCIDRDecorator(t *testing.T) {
	input := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	defer input.Close()
	outputQu := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider(defs(
		"10.0.0.0/8",
		"10.1.2.0/24",
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	), func(r *testRecord) *pipe.CommonAttrs { return &r.CommonAttrs },
		input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*testRecord{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Metadata["src.cidr"])
	assert.Empty(t, decorated[2].Metadata["dst.cidr"])
	assert.Empty(t, decorated[3].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Metadata["dst.cidr"])
}

func TestCIDRDecorator_GroupAllUnknownTraffic(t *testing.T) {
	input := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	defer input.Close()
	outputQu := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider(defs(
		"10.0.0.0/8",
		"10.1.2.0/24",
		"0.0.0.0/0", // this entry will capture all the unknown traffic
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	), func(r *testRecord) *pipe.CommonAttrs { return &r.CommonAttrs },
		input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*testRecord{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Metadata["src.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[2].Metadata["dst.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[3].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Metadata["dst.cidr"])
}

func TestCIDRDecorator_NamedCIDRs(t *testing.T) {
	input := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	defer input.Close()
	outputQu := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider(Definitions{
		{CIDR: "10.0.0.0/8", Name: "cluster-internal"},
		{CIDR: "10.1.2.0/24", Name: "pod-network"},
		{CIDR: "140.130.22.0/24", Name: "office"},
		{CIDR: "2001:db8:3c4d:15::/64", Name: "ipv6-pods"},
		{CIDR: "2001::/16"},
	}, func(r *testRecord) *pipe.CommonAttrs { return &r.CommonAttrs },
		input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*testRecord{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "cluster-internal", decorated[0].Metadata["src.cidr"])
	assert.Equal(t, "pod-network", decorated[0].Metadata["dst.cidr"])
	assert.Equal(t, "ipv6-pods", decorated[1].Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Metadata["dst.cidr"])
	assert.Equal(t, "office", decorated[2].Metadata["src.cidr"])
	assert.Empty(t, decorated[2].Metadata["dst.cidr"])
	assert.Empty(t, decorated[3].Metadata["src.cidr"])
	assert.Equal(t, "pod-network", decorated[3].Metadata["dst.cidr"])
}

func TestUnmarshalYAML_PlainStrings(t *testing.T) {
	yamlData := `
- 10.0.0.0/8
- 192.168.0.0/16
- 2001::/16
`
	var d Definitions
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &d))
	require.Len(t, d, 3)
	assert.Equal(t, Definition{CIDR: "10.0.0.0/8"}, d[0])
	assert.Equal(t, Definition{CIDR: "192.168.0.0/16"}, d[1])
	assert.Equal(t, Definition{CIDR: "2001::/16"}, d[2])
}

func TestUnmarshalYAML_NamedCIDRs(t *testing.T) {
	yamlData := `
- cidr: 10.0.0.0/8
  name: cluster-internal
- cidr: 192.168.0.0/16
  name: private
- cidr: 172.16.0.0/12
`
	var d Definitions
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &d))
	require.Len(t, d, 3)
	assert.Equal(t, Definition{CIDR: "10.0.0.0/8", Name: "cluster-internal"}, d[0])
	assert.Equal(t, Definition{CIDR: "192.168.0.0/16", Name: "private"}, d[1])
	assert.Equal(t, Definition{CIDR: "172.16.0.0/12"}, d[2])
}

func TestUnmarshalYAML_MixedFormats(t *testing.T) {
	yamlData := `
- 10.0.0.0/8
- cidr: 192.168.0.0/16
  name: private
- 172.16.0.0/12
`
	var d Definitions
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &d))
	require.Len(t, d, 3)
	assert.Equal(t, Definition{CIDR: "10.0.0.0/8"}, d[0])
	assert.Equal(t, Definition{CIDR: "192.168.0.0/16", Name: "private"}, d[1])
	assert.Equal(t, Definition{CIDR: "172.16.0.0/12"}, d[2])
}

func TestUnmarshalYAML_MissingCIDRField(t *testing.T) {
	yamlData := `
- name: missing-cidr
`
	var d Definitions
	err := yaml.Unmarshal([]byte(yamlData), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required 'cidr' field")
}

func TestUnmarshalText(t *testing.T) {
	var d Definitions
	require.NoError(t, d.UnmarshalText([]byte("10.0.0.0/8,192.168.0.0/16,2001::/16")))
	require.Len(t, d, 3)
	assert.Equal(t, "10.0.0.0/8", d[0].CIDR)
	assert.Empty(t, d[0].Name)
	assert.Equal(t, "192.168.0.0/16", d[1].CIDR)
	assert.Equal(t, "2001::/16", d[2].CIDR)
}

func TestUnmarshalText_Empty(t *testing.T) {
	var d Definitions
	require.NoError(t, d.UnmarshalText([]byte("")))
	assert.Nil(t, d)
}

func TestValidate(t *testing.T) {
	valid := Definitions{
		{CIDR: "10.0.0.0/8"},
		{CIDR: "192.168.0.0/16", Name: "private"},
	}
	require.NoError(t, valid.Validate())

	invalid := Definitions{
		{CIDR: "10.0.0.0/8"},
		{CIDR: "not-a-cidr", Name: "bad"},
	}
	err := invalid.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-cidr")
}

func TestDefinition_Label(t *testing.T) {
	assert.Equal(t, "my-network", Definition{CIDR: "10.0.0.0/8", Name: "my-network"}.Label())
	assert.Equal(t, "10.0.0.0/8", Definition{CIDR: "10.0.0.0/8"}.Label())
}

func TestEnvironmentVariableHandling(t *testing.T) {
	// Test that the environment variable handling of OTEL_EBPF_NETWORK_CIDRS still works
	// by verifying that comma-separated CIDR strings are correctly parsed.
	// This test ensures backward compatibility with the old behavior.
	// Note: UnmarshalText accepts any string and doesn't validate - validation is done
	// separately via the Validate() method which is called during config validation.

	tests := []struct {
		name     string
		envValue string
		expected Definitions
	}{
		{
			name:     "Single CIDR",
			envValue: "10.0.0.0/8",
			expected: Definitions{{CIDR: "10.0.0.0/8"}},
		},
		{
			name:     "Multiple CIDRs comma-separated",
			envValue: "10.0.0.0/8,192.168.0.0/16,2001::/16",
			expected: Definitions{
				{CIDR: "10.0.0.0/8"},
				{CIDR: "192.168.0.0/16"},
				{CIDR: "2001::/16"},
			},
		},
		{
			name:     "CIDRs with spaces around commas",
			envValue: "10.0.0.0/8 , 192.168.0.0/16 , 2001::/16",
			expected: Definitions{
				{CIDR: "10.0.0.0/8"},
				{CIDR: "192.168.0.0/16"},
				{CIDR: "2001::/16"},
			},
		},
		{
			name:     "Empty environment variable",
			envValue: "",
			expected: nil,
		},
		{
			name:     "Whitespace only",
			envValue: "   ",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Definitions
			err := d.UnmarshalText([]byte(tt.envValue))
			require.NoError(t, err)
			require.Equal(t, tt.expected, d)

			// Verify that valid definitions validate correctly
			if len(d) > 0 {
				require.NoError(t, d.Validate())
			}
		})
	}

	// Test that invalid CIDRs are caught during validation (not during unmarshaling)
	t.Run("Invalid CIDR format caught during validation", func(t *testing.T) {
		var d Definitions
		require.NoError(t, d.UnmarshalText([]byte("not-a-cidr")))
		err := d.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not-a-cidr")
	})

	t.Run("Mix of valid and invalid CIDRs caught during validation", func(t *testing.T) {
		var d Definitions
		require.NoError(t, d.UnmarshalText([]byte("10.0.0.0/8,invalid-cidr")))
		err := d.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid-cidr")
	})
}

func flow(srcIP, dstIP string) *testRecord {
	r := &testRecord{}
	copy(r.SrcAddr[:], net.ParseIP(srcIP).To16())
	copy(r.DstAddr[:], net.ParseIP(dstIP).To16())
	return r
}
