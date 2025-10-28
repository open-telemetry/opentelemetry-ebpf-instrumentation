// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func testMatch(t *testing.T, m Event[ProcessMatch], name string,
	namespace string, proc services.ProcessInfo,
) {
	assert.Equal(t, EventCreated, m.Type)
	require.Len(t, m.Obj.Criteria, 1)
	assert.Equal(t, name, m.Obj.Criteria[0].GetName())
	assert.Equal(t, namespace, m.Obj.Criteria[0].GetNamespace())
	assert.Equal(t, proc, *m.Obj.Process)
}

func TestCriteriaMatcher(t *testing.T) {
	pipeConfig := obi.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only
    namespace: foo
    open_ports: 80,8080-8089
  - name: exec-only
    exe_path: weird\d
  - name: both
    open_ports: 443
    exe_path_regexp: "server"
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := criteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/weird33", 2: "/bin/weird33", 3: "server",
			4: "/bin/something", 5: "server", 6: "/bin/clientweird99",
		}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1, openPorts: []uint32{1, 2, 3}}}, // pass
		{Type: EventDeleted, Obj: ProcessAttrs{pid: 2, openPorts: []uint32{4}}},       // filter
		{Type: EventCreated, Obj: ProcessAttrs{pid: 3, openPorts: []uint32{8433}}},    // filter
		{Type: EventCreated, Obj: ProcessAttrs{pid: 4, openPorts: []uint32{8083}}},    // pass
		{Type: EventCreated, Obj: ProcessAttrs{pid: 5, openPorts: []uint32{443}}},     // pass
		{Type: EventCreated, Obj: ProcessAttrs{pid: 6}},                               // pass
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 4)

	testMatch(t, matches[0], "exec-only", "", services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33", OpenPorts: []uint32{1, 2, 3}})
	testMatch(t, matches[1], "port-only", "foo", services.ProcessInfo{Pid: 4, ExePath: "/bin/something", OpenPorts: []uint32{8083}})
	testMatch(t, matches[2], "both", "", services.ProcessInfo{Pid: 5, ExePath: "server", OpenPorts: []uint32{443}})
	testMatch(t, matches[3], "exec-only", "", services.ProcessInfo{Pid: 6, ExePath: "/bin/clientweird99"})
}

func TestCriteriaMatcher_Exclude(t *testing.T) {
	pipeConfig := obi.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only
    namespace: foo
    open_ports: 80,8080-8089
  - name: exec-only
    exe_path: weird\d
  - name: both
    open_ports: 443
    exe_path_regexp: "server"
  exclude_services:
  - exe_path: s
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := criteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/weird33", 2: "/bin/weird33", 3: "server",
			4: "/bin/something", 5: "server", 6: "/bin/clientweird99",
		}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1, openPorts: []uint32{1, 2, 3}}}, // pass
		{Type: EventDeleted, Obj: ProcessAttrs{pid: 2, openPorts: []uint32{4}}},       // filter
		{Type: EventCreated, Obj: ProcessAttrs{pid: 3, openPorts: []uint32{8433}}},    // filter
		{Type: EventCreated, Obj: ProcessAttrs{pid: 4, openPorts: []uint32{8083}}},    // filter (in exclude)
		{Type: EventCreated, Obj: ProcessAttrs{pid: 5, openPorts: []uint32{443}}},     // filter (in exclude)
		{Type: EventCreated, Obj: ProcessAttrs{pid: 6}},                               // pass
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 2)

	testMatch(t, matches[0], "exec-only", "", services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33", OpenPorts: []uint32{1, 2, 3}})
	testMatch(t, matches[1], "exec-only", "", services.ProcessInfo{Pid: 6, ExePath: "/bin/clientweird99"})
}

func TestCriteriaMatcher_Exclude_Metadata(t *testing.T) {
	pipeConfig := obi.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - k8s_node_name: .
  exclude_services:
  - k8s_node_name: bar
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := criteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/weird33", 2: "/bin/weird33", 3: "server",
			4: "/bin/something", 5: "server", 6: "/bin/clientweird99",
		}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	nodeFoo := map[string]string{"k8s_node_name": "foo"}
	nodeBar := map[string]string{"k8s_node_name": "bar"}
	discoveredProcesses.Send([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1, metadata: nodeFoo}}, // pass
		{Type: EventDeleted, Obj: ProcessAttrs{pid: 2, metadata: nodeFoo}}, // filter
		{Type: EventCreated, Obj: ProcessAttrs{pid: 3, metadata: nodeFoo}}, // pass
		{Type: EventCreated, Obj: ProcessAttrs{pid: 4, metadata: nodeBar}}, // filter (in exclude)
		{Type: EventDeleted, Obj: ProcessAttrs{pid: 5, metadata: nodeFoo}}, // filter
		{Type: EventCreated, Obj: ProcessAttrs{pid: 6, metadata: nodeBar}}, // filter (in exclude)
	})

	matches := testutil.ReadChannel(t, filteredProcesses, 1000*testTimeout)
	require.Len(t, matches, 2)
	testMatch(t, matches[0], "", "", services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33"})
	testMatch(t, matches[1], "", "", services.ProcessInfo{Pid: 3, ExePath: "server"})
}

func TestCriteriaMatcher_MustMatchAllAttributes(t *testing.T) {
	pipeConfig := obi.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: all-attributes-must-match
    namespace: foons
    open_ports: 80,8080-8089
    exe_path: foo
    k8s_namespace: thens
    k8s_pod_name: thepod
    k8s_deployment_name: thedepl
    k8s_replicaset_name: thers
    k8s_container_name: foocontainer
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := criteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/foo", 2: "/bin/faa", 3: "foo",
			4: "foool", 5: "thefoool", 6: "foo",
		}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	allMeta := map[string]string{
		"k8s_namespace":       "thens",
		"k8s_pod_name":        "is-thepod",
		"k8s_deployment_name": "thedeployment",
		"k8s_replicaset_name": "thers",
		"k8s_container_name":  "foocontainer",
	}
	incompleteMeta := map[string]string{
		"k8s_namespace":       "thens",
		"k8s_pod_name":        "is-thepod",
		"k8s_replicaset_name": "thers",
	}
	differentMeta := map[string]string{
		"k8s_namespace":       "thens",
		"k8s_pod_name":        "is-thepod",
		"k8s_deployment_name": "some-deployment",
		"k8s_replicaset_name": "thers",
	}
	discoveredProcesses.Send([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1, openPorts: []uint32{8081}, metadata: allMeta}},        // pass
		{Type: EventDeleted, Obj: ProcessAttrs{pid: 2, openPorts: []uint32{4}, metadata: allMeta}},           // filter: executable does not match
		{Type: EventCreated, Obj: ProcessAttrs{pid: 3, openPorts: []uint32{7777}, metadata: allMeta}},        // filter: port does not match
		{Type: EventCreated, Obj: ProcessAttrs{pid: 4, openPorts: []uint32{8083}, metadata: incompleteMeta}}, // filter: not all metadata available
		{Type: EventCreated, Obj: ProcessAttrs{pid: 5, openPorts: []uint32{80}}},                             // filter: no metadata
		{Type: EventCreated, Obj: ProcessAttrs{pid: 6, openPorts: []uint32{8083}, metadata: differentMeta}},  // filter: not all metadata matches
	})
	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 1)
	testMatch(t, matches[0], "all-attributes-must-match", "foons", services.ProcessInfo{Pid: 1, ExePath: "/bin/foo", OpenPorts: []uint32{8081}})
}

func TestCriteriaMatcherMissingPort(t *testing.T) {
	pipeConfig := obi.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only
    namespace: foo
    open_ports: 80
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := criteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
		proc := map[PID]struct {
			Exe  string
			PPid int32
		}{
			1: {Exe: "/bin/weird33", PPid: 0}, 2: {Exe: "/bin/weird33", PPid: 16}, 3: {Exe: "/bin/weird33", PPid: 1},
		}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: proc.Exe, PPid: proc.PPid, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1, openPorts: []uint32{80}}}, // this one is the parent, matches on port
		{Type: EventDeleted, Obj: ProcessAttrs{pid: 2, openPorts: []uint32{}}},   // we'll skip 2 since PPid is 16, not 1
		{Type: EventCreated, Obj: ProcessAttrs{pid: 3, openPorts: []uint32{}}},   // this one is the child, without port, but matches the parent by port
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 2)
	testMatch(t, matches[0], "port-only", "foo", services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33", OpenPorts: []uint32{80}, PPid: 0})
	testMatch(t, matches[1], "port-only", "foo", services.ProcessInfo{Pid: 3, ExePath: "/bin/weird33", OpenPorts: []uint32{}, PPid: 1})
}

func TestCriteriaMatcherContainersOnly(t *testing.T) {
	pipeConfig := obi.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only-containers
    namespace: foo
    open_ports: 80
    containers_only: true
`), &pipeConfig))

	// override the namespace fetcher
	namespaceFetcherFunc = func(pid int32) (string, error) {
		switch pid {
		case 1:
			return "1", nil
		case 2:
			return "2", nil
		case 3:
			return "3", nil
		}
		panic("pid not exposed by test")
	}

	// override the os.Getpid func to that Beyla is always reported
	// with pid 1
	osPidFunc = func() int {
		return 1
	}

	discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := criteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
		proc := map[PID]struct {
			Exe  string
			PPid int32
		}{
			1: {Exe: "/bin/weird33", PPid: 0}, 2: {Exe: "/bin/weird33", PPid: 0}, 3: {Exe: "/bin/weird33", PPid: 1},
		}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: proc.Exe, PPid: proc.PPid, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1, openPorts: []uint32{80}}}, // this one is the parent, matches on port, not in container
		{Type: EventCreated, Obj: ProcessAttrs{pid: 2, openPorts: []uint32{80}}}, // another pid, but in a container
		{Type: EventCreated, Obj: ProcessAttrs{pid: 3, openPorts: []uint32{80}}}, // this one is the child, without port, but matches the parent by port, in a container
	})

	matches := testutil.ReadChannel(t, filteredProcesses, 5000*testTimeout)
	require.Len(t, matches, 2)
	testMatch(t, matches[0], "port-only-containers", "foo", services.ProcessInfo{Pid: 2, ExePath: "/bin/weird33", OpenPorts: []uint32{80}, PPid: 0})
	testMatch(t, matches[1], "port-only-containers", "foo", services.ProcessInfo{Pid: 3, ExePath: "/bin/weird33", OpenPorts: []uint32{80}, PPid: 1})
}

func TestInstrumentation_CoexistingWithDeprecatedServices(t *testing.T) {
	// setup conflicting criteria and see how some of them are ignored and others not
	type testCase struct {
		name string
		cfg  obi.Config
	}
	pass := services.NewGlob("*/must-pass")
	notPass := services.NewGlob("*/dont-pass")
	neitherPass := services.NewGlob("*/neither-pass")
	bothPass := services.NewGlob("*/{must,also}-pass")

	passPort := services.PortEnum{Ranges: []services.PortRange{{Start: 80}}}
	allPorts := services.PortEnum{Ranges: []services.PortRange{{Start: 1, End: 65535}}}

	passRE := services.NewRegexp("must-pass")
	notPassRE := services.NewRegexp("dont-pass")
	neitherPassRE := services.NewRegexp("neither-pass")
	bothPassRE := services.NewRegexp("(must|also)-pass")

	for _, tc := range []testCase{
		{name: "discovery > instrument", cfg: obi.Config{Discovery: services.DiscoveryConfig{
			Instrument: services.GlobDefinitionCriteria{{Path: pass}, {OpenPorts: passPort}},
		}}},
		{
			name: "discovery > instrument with discovery > exclude_instrument && default_exclude_instrument",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Instrument:               services.GlobDefinitionCriteria{{OpenPorts: allPorts}},
				ExcludeInstrument:        services.GlobDefinitionCriteria{{Path: notPass}},
				DefaultExcludeInstrument: services.GlobDefinitionCriteria{{Path: neitherPass}},
			}},
		},
		{
			name: "discovery > instrument with deprecated discovery > services",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{Path: pass}, {OpenPorts: passPort}},
				// To be ignored
				Services: services.RegexDefinitionCriteria{{OpenPorts: allPorts}},
			}},
		},
		{
			name: "discovery > instrument with top-level auto-target-exec option",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{OpenPorts: passPort}},
			}, AutoTargetExe: pass},
		},
		{
			name: "discovery > instrument with top-level ports option",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{Path: pass}},
			}, Port: passPort},
		},
		{
			name: "discovery > instrument ignoring deprecated path option",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{Path: pass}, {OpenPorts: passPort}},
			}, Exec: services.NewRegexp("dont-pass")},
		},
		// cases below would be removed if the deprecated discovery > services options are removed,
		{name: "deprecated discovery > services", cfg: obi.Config{Discovery: services.DiscoveryConfig{
			Services: services.RegexDefinitionCriteria{{Path: passRE}, {OpenPorts: passPort}},
		}}},
		{
			name: "deprecated discovery > services with discovery > exclude_services && default_exclude_services",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Services:               services.RegexDefinitionCriteria{{OpenPorts: allPorts}},
				ExcludeServices:        services.RegexDefinitionCriteria{{Path: notPassRE}},
				DefaultExcludeServices: services.RegexDefinitionCriteria{{Path: neitherPassRE}},
			}},
		},
		{
			name: "deprecated discovery > services with top-level deprecated exec option",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Services: services.RegexDefinitionCriteria{{OpenPorts: passPort}},
			}, Exec: passRE},
		},
		{
			name: "deprecated discovery > services with top-level deprecated port option",
			cfg: obi.Config{Discovery: services.DiscoveryConfig{
				Services: services.RegexDefinitionCriteria{{Path: passRE}},
			}, Port: passPort},
		},
		{
			name: "no YAML discovery section, using top-level AutoTargetExe variable",
			cfg:  obi.Config{AutoTargetExe: bothPass},
		},
		{
			name: "no YAML discovery section, using deprecated top-level discovery variables",
			cfg:  obi.Config{Exec: bothPassRE},
		},
		{name: "prioritizing top-level AutoTarget variable over deprecated exec", cfg: obi.Config{
			AutoTargetExe: bothPass,
			// to be ignored
			Exec: notPassRE,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// it will filter unmatching processes and return a ProcessMatch for these that match
			processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
				proc := map[PID]struct {
					Exe  string
					PPid int32
				}{
					1:  {Exe: "/bin/must-pass", PPid: 0},
					2:  {Exe: "/bin/also-pass", PPid: 0},
					11: {Exe: "/bin/dont-pass", PPid: 0},
					12: {Exe: "/bin/neither-pass", PPid: 0},
				}[pp.pid]
				return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: proc.Exe, PPid: proc.PPid, OpenPorts: pp.openPorts}, nil
			}
			discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
			filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
			filteredProcesses := filteredProcessesQu.Subscribe()
			matcherFunc, err := criteriaMatcherProvider(&tc.cfg, discoveredProcesses, filteredProcessesQu)(t.Context())
			require.NoError(t, err)
			go matcherFunc(t.Context())
			defer filteredProcessesQu.Close()

			discoveredProcesses.Send([]Event[ProcessAttrs]{
				{Type: EventCreated, Obj: ProcessAttrs{pid: 1, openPorts: []uint32{1234}}},
				{Type: EventCreated, Obj: ProcessAttrs{pid: 2, openPorts: []uint32{80}}},
				{Type: EventCreated, Obj: ProcessAttrs{pid: 11, openPorts: []uint32{4321}}},
				{Type: EventCreated, Obj: ProcessAttrs{pid: 12, openPorts: []uint32{3456}}},
			})

			matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
			require.Len(t, matches, 2)
			m := matches[0]
			assert.Equal(t, EventCreated, m.Type)
			assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/must-pass", OpenPorts: []uint32{1234}}, *m.Obj.Process)
			m = matches[1]
			assert.Equal(t, EventCreated, m.Type)
			assert.Equal(t, services.ProcessInfo{Pid: 2, ExePath: "/bin/also-pass", OpenPorts: []uint32{80}}, *m.Obj.Process)
		})
	}
}

func TestCriteriaMatcher_Granular(t *testing.T) {
	pipeConfig := obi.Config{}

	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  instrument:
  - k8s_namespace: default
    exports: [metrics]
  - k8s_deployment_name: planet-service
    exports: [traces]
    sampler:
        name: traceidratio
        arg: 0.5
  - k8s_deployment_name: satellite-service
    exports: []
  - k8s_deployment_name: star-service
  - k8s_deployment_name: asteroid-service
    exports: [metrics, traces]
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))

	filteredProcesses := filteredProcessesQu.Subscribe()

	matcherFunc, err := criteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())

	require.NoError(t, err)

	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/planet-service",
			2: "/bin/satellite-service",
			3: "/bin/star-service",
			4: "/bin/asteroid-service",
		}[pp.pid]

		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}

	discoveredProcesses.Send([]Event[ProcessAttrs]{
		{
			Type: EventCreated,
			Obj: ProcessAttrs{
				pid: 1,
				metadata: map[string]string{
					"k8s_namespace":       "default",
					"k8s_deployment_name": "planet-service",
				},
			},
		},
		{
			Type: EventCreated,
			Obj: ProcessAttrs{
				pid: 2,
				metadata: map[string]string{
					"k8s_namespace":       "default",
					"k8s_deployment_name": "satellite-service",
				},
			},
		},
		{
			Type: EventCreated,
			Obj: ProcessAttrs{
				pid: 3,
				metadata: map[string]string{
					"k8s_namespace":       "default",
					"k8s_deployment_name": "star-service",
				},
			},
		},
		{
			Type: EventCreated,
			Obj: ProcessAttrs{
				pid: 4,
				metadata: map[string]string{
					"k8s_namespace":       "default",
					"k8s_deployment_name": "asteroid-service",
				},
			},
		},
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 4)

	planetMatch := matches[0].Obj

	require.Len(t, planetMatch.Criteria, 2)

	planetAttrs := makeServiceAttrs(&planetMatch)

	assert.True(t, planetAttrs.ExportModes.CanExportTraces())
	assert.False(t, planetAttrs.ExportModes.CanExportMetrics())
	require.NotNil(t, planetAttrs.Sampler)
	assert.Equal(t, "TraceIDRatioBased{0.5}", planetAttrs.Sampler.Description())

	satelliteMatch := matches[1].Obj

	require.Len(t, satelliteMatch.Criteria, 2)

	satelliteAttrs := makeServiceAttrs(&satelliteMatch)

	assert.False(t, satelliteAttrs.ExportModes.CanExportTraces())
	assert.False(t, satelliteAttrs.ExportModes.CanExportMetrics())
	require.Nil(t, satelliteAttrs.Sampler)

	starMatch := matches[2].Obj

	require.Len(t, starMatch.Criteria, 2)

	starAttrs := makeServiceAttrs(&starMatch)

	assert.False(t, starAttrs.ExportModes.CanExportTraces())
	assert.True(t, starAttrs.ExportModes.CanExportMetrics())
	require.Nil(t, starAttrs.Sampler)

	asteroidMatch := matches[3].Obj

	require.Len(t, asteroidMatch.Criteria, 2)

	asteroidAttrs := makeServiceAttrs(&asteroidMatch)

	assert.True(t, asteroidAttrs.ExportModes.CanExportTraces())
	assert.True(t, asteroidAttrs.ExportModes.CanExportMetrics())
	require.Nil(t, asteroidAttrs.Sampler)
}
