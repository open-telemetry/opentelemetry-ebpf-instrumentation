// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestNetworkEnumsYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		valid   string
		want    string
		invalid string
		err     string
		parse   func([]byte) (string, error)
	}{
		{
			name:    "network source",
			valid:   "source: socket_filter\n",
			want:    string(NetworkSourceSocketFilter),
			invalid: "source: raw_socket\n",
			err:     "invalid source",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Source NetworkSource `yaml:"source"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Source), err
			},
		},
		{
			name:    "agent ip family",
			valid:   "agent_ip_family: ipv6\n",
			want:    string(AgentIPFamilyIPv6),
			invalid: "agent_ip_family: ipx\n",
			err:     "invalid agent_ip_family",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Family AgentIPFamily `yaml:"agent_ip_family"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Family), err
			},
		},
		{
			name:    "network direction",
			valid:   "direction: both\n",
			want:    string(NetworkDirectionBoth),
			invalid: "direction: sideways\n",
			err:     "invalid direction",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Direction NetworkDirection `yaml:"direction"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Direction), err
			},
		},
		{
			name:    "deduplication strategy",
			valid:   "strategy: first_come\n",
			want:    string(DeduplicationStrategyFirstCome),
			invalid: "strategy: newest\n",
			err:     "invalid strategy",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Strategy DeduplicationStrategy `yaml:"strategy"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Strategy), err
			},
		},
		{
			name:    "interface discovery mode",
			valid:   "mode: poll\n",
			want:    string(InterfaceDiscoveryModePoll),
			invalid: "mode: scan\n",
			err:     "invalid mode",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Mode InterfaceDiscoveryMode `yaml:"mode"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Mode), err
			},
		},
		{
			name:    "reverse dns mode",
			valid:   "mode: ebpf\n",
			want:    string(ReverseDNSModeEBPF),
			invalid: "mode: remote\n",
			err:     "invalid mode",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Mode ReverseDNSMode `yaml:"mode"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Mode), err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := test.parse([]byte(test.valid))
			require.NoError(t, err)
			require.Equal(t, test.want, got)

			_, err = test.parse([]byte(test.invalid))
			require.Error(t, err)
			require.Contains(t, err.Error(), test.err)
		})
	}
}

func TestAgentIPInterfaceYAML(t *testing.T) {
	t.Parallel()

	t.Run("direct null", func(t *testing.T) {
		t.Parallel()

		got := AgentIPInterfaceLocal

		require.NoError(t, got.UnmarshalYAML(&yaml.Node{Tag: "!!null"}))
		require.Equal(t, AgentIPInterface(""), got)
	})

	tests := []struct {
		name string
		yaml string
		want AgentIPInterface
		err  string
	}{
		{
			name: "external",
			yaml: "agent_ip_interface: external\n",
			want: AgentIPInterfaceExternal,
		},
		{
			name: "local",
			yaml: "agent_ip_interface: local\n",
			want: AgentIPInterfaceLocal,
		},
		{
			name: "name",
			yaml: "agent_ip_interface: \"name:eth0\"\n",
			want: AgentIPInterface("name:eth0"),
		},
		{
			name: "null",
			yaml: "agent_ip_interface:\n",
			want: "",
		},
		{
			name: "empty name",
			yaml: "agent_ip_interface: \"name:\"\n",
			err:  "invalid agent_ip_interface",
		},
		{
			name: "invalid",
			yaml: "agent_ip_interface: eno1\n",
			err:  "invalid agent_ip_interface",
		},
		{
			name: "non scalar",
			yaml: "agent_ip_interface: []\n",
			err:  "agent_ip_interface must be a scalar",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var doc struct {
				Interface AgentIPInterface `yaml:"agent_ip_interface"`
			}

			err := yaml.Unmarshal([]byte(test.yaml), &doc)
			if test.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, doc.Interface)
		})
	}
}

func TestCIDRDefinitionsYAML(t *testing.T) {
	t.Parallel()

	var doc struct {
		CIDRs CIDRDefinitions `yaml:"cidrs"`
	}

	err := yaml.Unmarshal([]byte(`
cidrs:
  - 10.0.0.0/8
  - cidr: 192.168.0.0/16
    name: private
`), &doc)
	require.NoError(t, err)
	require.Equal(t, CIDRDefinitions{
		{CIDR: "10.0.0.0/8"},
		{CIDR: "192.168.0.0/16", Name: "private"},
	}, doc.CIDRs)
}

func TestCIDRDefinitionsRejectsInvalidYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		err  string
	}{
		{
			name: "not sequence",
			yaml: "cidrs: {}\n",
			err:  "expected a YAML sequence",
		},
		{
			name: "mapping missing cidr",
			yaml: "cidrs:\n  - name: private\n",
			err:  "missing required 'cidr' field",
		},
		{
			name: "unexpected item kind",
			yaml: "cidrs:\n  - []\n",
			err:  "unexpected YAML node kind",
		},
		{
			name: "invalid mapping field type",
			yaml: "cidrs:\n  - cidr: []\n",
			err:  "cidrs[0]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var doc struct {
				CIDRs CIDRDefinitions `yaml:"cidrs"`
			}

			err := yaml.Unmarshal([]byte(test.yaml), &doc)
			require.Error(t, err)
			require.Contains(t, err.Error(), test.err)
		})
	}
}
