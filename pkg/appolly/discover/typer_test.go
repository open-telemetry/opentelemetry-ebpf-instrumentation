// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"io"
	"iter"
	"log/slog"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/selection"
	"go.opentelemetry.io/obi/pkg/transform"
)

type dummyCriterion struct {
	name      string
	namespace string
	export    services.ExportModes
	sampler   *services.SamplerConfig
	routes    *services.CustomRoutesConfig
	features  export.Features
}

func (d dummyCriterion) GetName() string { return d.name }

func (d dummyCriterion) GetOpenPorts() *services.IntEnum { return nil }

func (d dummyCriterion) GetPath() services.StringMatcher { return nil }

func (d dummyCriterion) GetLanguages() services.StringMatcher { return nil }

func (d dummyCriterion) RangeMetadata() iter.Seq2[string, services.StringMatcher] { return nil }

func (d dummyCriterion) RangePodAnnotations() iter.Seq2[string, services.StringMatcher] { return nil }

func (d dummyCriterion) RangePodLabels() iter.Seq2[string, services.StringMatcher] { return nil }

func (d dummyCriterion) IsContainersOnly() bool { return false }

func (d dummyCriterion) GetPathRegexp() services.StringMatcher { return nil }

func (d dummyCriterion) GetCmdArgs() services.StringMatcher { return nil }

func (d dummyCriterion) GetPIDs() ([]app.PID, bool) { return nil, false }

func (d dummyCriterion) GetNamespace() string { return d.namespace }

func (d dummyCriterion) GetExportModes() services.ExportModes { return d.export }

func (d dummyCriterion) GetSamplerConfig() *services.SamplerConfig { return d.sampler }

func (d dummyCriterion) GetRoutesConfig() *services.CustomRoutesConfig { return d.routes }

func (d dummyCriterion) MetricsConfig() perapp.SvcMetricsConfig {
	return perapp.SvcMetricsConfig{Features: d.features}
}

func TestLoadAllGoFunctionNamesIncludesConditionalGoTracerSymbols(t *testing.T) {
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{}}}
	ty.loadAllGoFunctionNames()

	for _, symbol := range gotracer.GoChannelLinkProbeSymbols() {
		assert.Contains(t, ty.allGoFunctions, symbol)
	}
	for _, symbol := range gotracer.GoRuntimeMetricProbeSymbols() {
		assert.Contains(t, ty.allGoFunctions, symbol)
	}
	for _, symbol := range gotracer.GoAutoSDKActivationProbeSymbols() {
		assert.Contains(t, ty.allGoFunctions, symbol)
	}
	for _, symbol := range gotracer.GoHTTP2FlushProbeSymbols() {
		assert.Contains(t, ty.allGoFunctions, symbol)
	}
	for _, symbol := range gotracer.GoH2OwnershipProbeSymbols() {
		assert.Contains(t, ty.allGoFunctions, symbol)
	}
}

func TestLoadAllGoFunctionNamesIncludesExceptionSymbolsOnlyWhenCapturing(t *testing.T) {
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{}}}
	ty.loadAllGoFunctionNames()
	for _, symbol := range gotracer.GoExceptionProbeSymbols() {
		assert.NotContains(t, ty.allGoFunctions, symbol)
	}

	ty.cfg.Exceptions.Enabled = true
	ty.cfg.Logs.Protocol = otelcfg.ProtocolDebug
	ty.loadAllGoFunctionNames()
	for _, symbol := range gotracer.GoExceptionProbeSymbols() {
		assert.Contains(t, ty.allGoFunctions, symbol)
	}
}

func TestExceptionSymbolsDoNotQualifyGoProxy(t *testing.T) {
	funcs := map[string][]goexec.FuncOffsets{"runtime.chansend1": {}}
	for _, symbol := range gotracer.GoExceptionProbeSymbols() {
		funcs[symbol] = []goexec.FuncOffsets{}
	}
	assert.True(t, isGoProxy(&goexec.Offsets{Funcs: funcs}))
}

func TestContextWithValueDoesNotQualifyGoProxy(t *testing.T) {
	assert.True(t, isGoProxy(&goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{
		"runtime.chansend1": {},
		"context.WithValue": {},
	}}))
	assert.False(t, isGoProxy(&goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{
		"runtime.chansend1":                {},
		"context.WithValue":                {},
		"net/http.serverHandler.ServeHTTP": {},
	}}))
}

func TestMakeServiceAttrs(t *testing.T) {
	pi := services.ProcessInfo{Pid: 1234}
	proc := &ProcessMatch{
		Process: &pi,
		Criteria: []services.Selector{
			dummyCriterion{name: "svc1", namespace: "ns1", export: services.ExportModeUnset},
		},
	}
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{}}}
	attrs := ty.makeServiceAttrs(proc)
	assert.Equal(t, "svc1", attrs.UID.Name)
	assert.Equal(t, "ns1", attrs.UID.Namespace)
	assert.EqualValues(t, 1234, attrs.ProcPID)
	assert.Equal(t, services.ExportModeUnset, attrs.ExportModes)
	assert.Nil(t, attrs.SamplerConfig)

	// Test with sampler and routes
	sampler := &services.SamplerConfig{}
	routes := &services.CustomRoutesConfig{
		Incoming: []string{"/test"},
		Outgoing: []string{"/test2"},
	}
	pi2 := services.ProcessInfo{Pid: 5678}
	proc2 := &ProcessMatch{
		Process: &pi2,
		Criteria: []services.Selector{
			dummyCriterion{sampler: sampler, routes: routes},
		},
	}
	attrs2 := ty.makeServiceAttrs(proc2)
	assert.NotNil(t, attrs2.Sampler)
	assert.Same(t, sampler, attrs2.SamplerConfig)
	assert.NotNil(t, attrs2.CustomInRouteMatcher)
	assert.NotNil(t, attrs2.CustomOutRouteMatcher)
}

func TestMakeServiceAttrsUsesGlobalServiceIdentityWithDiscoveryRules(t *testing.T) {
	pi := services.ProcessInfo{Pid: 1234}
	cfg := &obi.Config{
		ServiceName:      "checkout",
		ServiceNamespace: "shop",
		Discovery: services.DiscoveryConfig{
			Instrument: services.GlobDefinitionCriteria{
				{Path: services.NewGlob("/app/*")},
			},
		},
	}
	ty := typer{cfg: cfg}

	// A capture rule selects the process but does not define a service identity.
	attrs := ty.makeServiceAttrs(&ProcessMatch{
		Process:  &pi,
		Criteria: FindingCriteria(cfg),
	})
	assert.Equal(t, "checkout", attrs.UID.Name)
	assert.Equal(t, "shop", attrs.UID.Namespace)

	// Explicit selector identity retains precedence over the global resource.
	attrs = ty.makeServiceAttrs(&ProcessMatch{
		Process:  &pi,
		Criteria: []services.Selector{dummyCriterion{name: "payments", namespace: "billing"}},
	})
	assert.Equal(t, "payments", attrs.UID.Name)
	assert.Equal(t, "billing", attrs.UID.Namespace)
}

func TestMakeServiceAttrsDefaultsSDKLanguageToGeneric(t *testing.T) {
	pi := services.ProcessInfo{Pid: 1234}
	proc := &ProcessMatch{
		Process:  &pi,
		Criteria: []services.Selector{dummyCriterion{name: "svc1"}},
	}
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{}}}

	attrs := ty.makeServiceAttrs(proc)

	assert.Equal(t, svc.InstrumentableGeneric, attrs.SDKLanguage)
	assert.Equal(t, "generic", attrs.SDKLanguage.String())
}

func TestMakeServiceAttrs_DynamicOptions(t *testing.T) {
	d := NewDynamicSelector()
	d.Traces().AddPID(42, selection.DynamicOptions{
		ServiceName:      "dynamic-svc",
		ServiceNamespace: "dynamic-ns",
		ResourceAttributes: map[string]string{
			"deployment.environment": "prod",
		},
	})
	selector := d.appSignals().SelectorForPID(42)
	require.NotNil(t, selector)

	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{}}}
	attrs := ty.makeServiceAttrs(&ProcessMatch{
		Process:            &services.ProcessInfo{Pid: 42},
		Criteria:           []services.Selector{selector},
		DynamicSelectorPID: 42,
	})
	assert.Equal(t, "dynamic-svc", attrs.UID.Name)
	assert.Equal(t, "dynamic-ns", attrs.UID.Namespace)
	assert.Equal(t, "prod", attrs.Metadata[attr.Name("deployment.environment")])
}

func TestMakeServiceAttrsDirectionalRouteOverrides(t *testing.T) {
	global := services.DirectionalRoutePolicies{
		Incoming: services.RoutePolicy{
			Unmatch:        services.UnmatchHeuristic,
			Patterns:       []string{"/global/{id}"},
			IgnorePatterns: []string{"/health"},
		},
		Outgoing: services.RoutePolicy{
			Unmatch:  services.UnmatchWildcard,
			Patterns: []string{"/outgoing/{id}"},
		},
	}
	patterns := []string{"/service/{id}"}
	unmatched := services.UnmatchPath
	routes := &services.CustomRoutesConfig{
		PolicyOverrides: &services.DirectionalRoutePolicyOverrides{
			Incoming: &services.RoutePolicyOverride{
				Patterns: &patterns,
				Unmatch:  &unmatched,
			},
		},
	}
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{Directional: &global}}}
	attrs := ty.makeServiceAttrs(&ProcessMatch{
		Process: &services.ProcessInfo{Pid: 1234},
		Criteria: []services.Selector{
			dummyCriterion{routes: routes},
		},
	})

	require.NotNil(t, attrs.IncomingRoutePolicy)
	require.Nil(t, attrs.OutgoingRoutePolicy)
	assert.Equal(t, services.UnmatchPath, attrs.IncomingRoutePolicy.Config.Unmatch)
	assert.Equal(t, "/service/{id}", attrs.IncomingRoutePolicy.Matcher.Find("/service/123"))
	assert.Equal(t, "/health", attrs.IncomingRoutePolicy.IgnoreMatcher.Find("/health"))
}

func TestMakeServiceAttrsPreservesAbsentGlobalRouteDirection(t *testing.T) {
	global := services.DirectionalRoutePolicies{
		Incoming: services.RoutePolicy{Unmatch: services.UnmatchPath},
	}
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{
		Directional: &global,
		DirectionalPolicyPresence: &transform.DirectionalRoutePolicyPresence{
			Incoming: true,
		},
	}}}

	globalOnly := ty.makeServiceAttrs(&ProcessMatch{
		Process:  &services.ProcessInfo{Pid: 1234},
		Criteria: []services.Selector{dummyCriterion{}},
	})
	require.Nil(t, globalOnly.IncomingRoutePolicy)
	require.Nil(t, globalOnly.OutgoingRoutePolicy)

	outgoingPatterns := []string{"/inventory/{id}"}
	withOverride := ty.makeServiceAttrs(&ProcessMatch{
		Process: &services.ProcessInfo{Pid: 5678},
		Criteria: []services.Selector{dummyCriterion{routes: &services.CustomRoutesConfig{
			PolicyOverrides: &services.DirectionalRoutePolicyOverrides{
				Outgoing: &services.RoutePolicyOverride{Patterns: &outgoingPatterns},
			},
		}}},
	})
	require.Nil(t, withOverride.IncomingRoutePolicy)
	require.NotNil(t, withOverride.OutgoingRoutePolicy)
	assert.Equal(t, "/inventory/{id}", withOverride.OutgoingRoutePolicy.Matcher.Find("/inventory/123"))
}

func TestMakeServiceAttrsKeepsGlobalCardinalityPerService(t *testing.T) {
	global := services.DirectionalRoutePolicies{
		Incoming: services.RoutePolicy{
			Unmatch:                   services.UnmatchLowCardinality,
			MaxPathSegmentCardinality: 2,
		},
		Outgoing: services.RoutePolicy{Unmatch: services.UnmatchPath},
	}
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{Directional: &global}}}

	first := ty.makeServiceAttrs(&ProcessMatch{
		Process:  &services.ProcessInfo{Pid: 1234},
		Criteria: []services.Selector{dummyCriterion{}},
	})
	second := ty.makeServiceAttrs(&ProcessMatch{
		Process:  &services.ProcessInfo{Pid: 5678},
		Criteria: []services.Selector{dummyCriterion{}},
	})

	assert.Nil(t, first.IncomingRoutePolicy)
	assert.Nil(t, first.OutgoingRoutePolicy)
	require.NotNil(t, first.IncomingPathTrie)
	require.NotNil(t, second.IncomingPathTrie)
	assert.NotSame(t, first.IncomingPathTrie, second.IncomingPathTrie)
	assert.Nil(t, first.OutgoingPathTrie)
}

func TestMakeServiceAttrsRuleOnlyDirectionalRoutes(t *testing.T) {
	baseline := services.DirectionalRoutePolicies{
		Incoming: services.RoutePolicy{Unmatch: services.UnmatchUnset},
		Outgoing: services.RoutePolicy{Unmatch: services.UnmatchUnset},
	}
	patterns := []string{"/service/{id}"}
	routes := &services.CustomRoutesConfig{
		PolicyOverrides: &services.DirectionalRoutePolicyOverrides{
			Incoming: &services.RoutePolicyOverride{Patterns: &patterns},
		},
	}
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{
		Directional:         &baseline,
		DirectionalRuleOnly: true,
	}}}

	matched := ty.makeServiceAttrs(&ProcessMatch{
		Process:  &services.ProcessInfo{Pid: 1234},
		Criteria: []services.Selector{dummyCriterion{routes: routes}},
	})
	require.NotNil(t, matched.IncomingRoutePolicy)
	assert.Equal(t, "/service/{id}", matched.IncomingRoutePolicy.Matcher.Find("/service/123"))
	assert.Nil(t, matched.OutgoingRoutePolicy)

	unmatched := ty.makeServiceAttrs(&ProcessMatch{
		Process:  &services.ProcessInfo{Pid: 5678},
		Criteria: []services.Selector{dummyCriterion{}},
	})
	assert.Nil(t, unmatched.IncomingRoutePolicy)
	assert.Nil(t, unmatched.OutgoingRoutePolicy)
}

func TestMakeServiceAttrs_FeaturesMatchingMultipleCriteria(t *testing.T) {
	exTra := services.ExportModes{}
	exTra.AllowTraces()
	exMet := services.ExportModes{}
	exMet.AllowMetrics()

	type testCase struct {
		name     string
		criteria []services.Selector
		expected export.Features
	}

	for _, tc := range []testCase{{
		name: "last match wins",
		criteria: []services.Selector{
			dummyCriterion{export: exMet, features: export.FeatureGraph},
			dummyCriterion{
				export: exTra, name: "svc1", namespace: "ns1",
				features: export.FeatureApplicationRED | export.FeatureGraph,
			},
		},
		expected: export.FeatureApplicationRED | export.FeatureGraph,
	}, {
		name: "if no features are defined, global metrics features prevail",
		criteria: []services.Selector{
			dummyCriterion{export: exTra, name: "svc2", namespace: "ns2"},
			dummyCriterion{name: "svc1", namespace: "ns1"},
		},
		expected: export.FeatureSpanOTel,
	}, {
		name: "if last match does not define features, global metrics config override any prior match",
		criteria: []services.Selector{
			dummyCriterion{name: "svc2", namespace: "ns2", features: export.FeatureGraph},
			dummyCriterion{export: exTra, name: "svc1", namespace: "ns1"},
		},
		expected: export.FeatureSpanOTel,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			proc := &ProcessMatch{
				Process:  &services.ProcessInfo{Pid: 1234},
				Criteria: tc.criteria,
			}
			ty := typer{cfg: &obi.Config{
				Routes:  &transform.RoutesConfig{},
				Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureSpanOTel},
			}}
			attrs := ty.makeServiceAttrs(proc)
			assert.Equal(t, "svc1", attrs.UID.Name)
			assert.Equal(t, "ns1", attrs.UID.Namespace)
			assert.EqualValues(t, 1234, attrs.ProcPID)

			// the later matching criteria prevails
			assert.Equal(t, exTra, attrs.ExportModes)
			assert.Equal(t, tc.expected, attrs.Features)
		})
	}
}

func TestClassificationAcrossRestarts(t *testing.T) {
	ty := newRestartTestTyper(t)
	original := findProcLanguage
	defer func() { findProcLanguage = original }()
	want := []svc.InstrumentableType{svc.InstrumentableGeneric, svc.InstrumentableDotnet, svc.InstrumentableGeneric}
	calls := 0
	findProcLanguage = func(pid app.PID) (svc.InstrumentableType, error) {
		calls++
		return want[int(pid)-1], nil
	}
	for i, lang := range want {
		pid := app.PID(i + 1)
		info := exec.New(exec.Init{Pid: pid, Dev: 42, Ino: 15, ChangeTime: 123, Service: svc.Attrs{LogEnricherEnabled: i%2 == 0}})
		ty.currentPids[pid] = info
		result := ty.asInstrumentable(info)
		require.Same(t, info, result.FileInfo)
		require.Equal(t, lang, result.Type)
		require.NoError(t, result.InstrumentationError)
		require.Equal(t, info.LogEnricherEnabled(), result.LogEnricherEnabled)

		deleted := ty.FilterClassify([]Event[ProcessMatch]{{Type: EventDeleted, Obj: ProcessMatch{Process: &services.ProcessInfo{Pid: pid}}}})
		require.Len(t, deleted, 1)
		require.Equal(t, EventDeleted, deleted[0].Type)
		require.Same(t, info, deleted[0].Obj.FileInfo)
		require.Empty(t, ty.currentPids)
	}
	require.Equal(t, len(want), calls)
}

func TestAsInstrumentable_PythonWorkerPreservesLogEnricherEnabled(t *testing.T) {
	origFindProcLanguage := findProcLanguage
	findProcLanguage = func(_ app.PID) (svc.InstrumentableType, error) {
		return svc.InstrumentablePython, nil
	}
	defer func() { findProcLanguage = origFindProcLanguage }()

	goOffsetsCache, err := lru.New[cacheKey, goInspectionResult](100)
	require.NoError(t, err)

	master := exec.New(exec.Init{
		Pid: 100, Dev: 42, Ino: 15, CmdExePath: "/usr/bin/python",
		Service: svc.Attrs{LogEnricherEnabled: false},
	})
	worker := exec.New(exec.Init{
		Pid: 101, Ppid: 100, Dev: 42, Ino: 15, CmdExePath: "/usr/bin/python",
		Service: svc.Attrs{LogEnricherEnabled: true},
	})

	ty := typer{
		log: slog.Default(),
		cfg: &obi.Config{
			Discovery: services.DiscoveryConfig{SkipGoSpecificTracers: true},
		},
		currentPids: map[app.PID]*exec.FileInfo{
			master.Pid(): master,
			worker.Pid(): worker,
		},
		goOffsetsCache: goOffsetsCache,
	}

	instrumentable := ty.asInstrumentable(worker)

	assert.Equal(t, svc.InstrumentablePython, instrumentable.Type)
	assert.Same(t, worker, instrumentable.FileInfo)
	assert.Same(t, master, worker.RuntimeMetricServiceSource())
	assert.True(t, instrumentable.LogEnricherEnabled)
}

func TestAsInstrumentable_PreservesWorkerIdentity(t *testing.T) {
	original := findProcLanguage
	t.Cleanup(func() { findProcLanguage = original })

	for _, typ := range []svc.InstrumentableType{svc.InstrumentableNodejs, svc.InstrumentableJava, svc.InstrumentableRuby} {
		t.Run(typ.String(), func(t *testing.T) {
			findProcLanguage = func(app.PID) (svc.InstrumentableType, error) { return typ, nil }
			parent := exec.New(exec.Init{Pid: 100, Dev: 42, Ino: 15, CmdExePath: "/opt/runtime"})
			worker := exec.New(exec.Init{
				Pid: 101, Ppid: 100, Dev: 42, Ino: 15, CmdExePath: "/opt/runtime",
				Service: svc.Attrs{LogEnricherEnabled: true},
			})
			cache, err := lru.New[cacheKey, goInspectionResult](100)
			require.NoError(t, err)
			ty := typer{
				log:            slog.Default(),
				cfg:            &obi.Config{},
				currentPids:    map[app.PID]*exec.FileInfo{parent.Pid(): parent, worker.Pid(): worker},
				goOffsetsCache: cache,
			}

			for _, process := range []*exec.FileInfo{parent, worker} {
				got := ty.asInstrumentable(process)
				assert.Equal(t, typ, got.Type)
				assert.Same(t, process, got.FileInfo)
				assert.Equal(t, process.LogEnricherEnabled(), got.LogEnricherEnabled)
				assert.Empty(t, got.ChildPids)
			}
		})
	}
}

func TestMakeServiceAttrsExceptionSelection(t *testing.T) {
	enabled, disabled := true, false
	cfg := obi.DefaultConfig
	cfg.Logs.Endpoint = "http://localhost:4318/v1/logs"
	cfg.Exceptions.Enabled = true
	ty := typer{cfg: &cfg}
	allow := &services.GlobAttributes{Exceptions: &services.ExceptionsOverride{Enabled: &enabled}}
	deny := &services.GlobAttributes{Exceptions: &services.ExceptionsOverride{Enabled: &disabled}}
	inherit := &services.GlobAttributes{}
	blocked := &services.GlobAttributes{ExportModes: services.NewExportModes(), Exceptions: &services.ExceptionsOverride{Enabled: &enabled}}
	for _, tc := range []struct {
		name     string
		criteria []services.Selector
		want     bool
	}{
		{"global", nil, true},
		{"explicit false", []services.Selector{deny}, false},
		{"later explicit true", []services.Selector{deny, allow}, true},
		{"omission restores global", []services.Selector{deny, inherit}, true},
		{"export blocks acquisition", []services.Selector{blocked}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ty.makeServiceAttrs(&ProcessMatch{Process: &services.ProcessInfo{Pid: 1234}, Criteria: tc.criteria})
			require.Equal(t, tc.want, got.Exceptions.Enabled)
		})
	}
	cfg.Logs.Endpoint = ""
	got := ty.makeServiceAttrs(&ProcessMatch{Process: &services.ProcessInfo{Pid: 1234}, Criteria: []services.Selector{allow}})
	require.False(t, got.Exceptions.Enabled)
}

func TestSelectorExceptionsCompatibility(t *testing.T) {
	assert.Nil(t, selectorExceptions(dummyCriterion{}))
	override := &services.ExceptionsOverride{}
	assert.Same(t, override, selectorExceptions(&services.GlobAttributes{Exceptions: override}))
}

func TestGoExecutableRestart(t *testing.T) {
	if os.Getenv("OBI_TEST_WAIT_FOR_EXIT") == "1" {
		_, err := io.Copy(io.Discard, os.Stdin)
		require.NoError(t, err)
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("requires procfs")
	}
	self, err := os.Executable()
	require.NoError(t, err)
	source, err := os.Open(self)
	require.NoError(t, err)
	defer source.Close()
	path := filepath.Join(t.TempDir(), "service")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o700)
	require.NoError(t, err)
	_, err = io.Copy(target, source)
	require.NoError(t, target.Close())
	require.NoError(t, err)
	ty := newRestartTestTyper(t)
	inspect := func(t *testing.T) ebpf.Instrumentable {
		t.Helper()
		cmd := osexec.Command(path, "-test.run=^TestGoExecutableRestart$")
		cmd.Env = append(os.Environ(), "OBI_TEST_WAIT_FOR_EXIT=1")
		return classifyUntilExit(t, ty, cmd)
	}
	functions := ty.allGoFunctions
	ty.allGoFunctions = []string{"missing.probe"}
	failed := inspect(t)
	require.Equal(t, svc.InstrumentableGolang, failed.Type)
	require.ErrorIs(t, failed.InstrumentationError, goexec.ErrNoInstrumentationPoints)

	// With matching probes restored, a fresh inspection would succeed.
	ty.allGoFunctions = functions
	cached := inspect(t)
	require.Equal(t, executableCacheKey(failed.FileInfo), executableCacheKey(cached.FileInfo))
	require.ErrorIs(t, cached.InstrumentationError, goexec.ErrNoInstrumentationPoints)

	require.NoError(t, os.Chmod(path, 0o750))
	first := inspect(t)
	require.NoError(t, first.InstrumentationError)
	require.NotNil(t, first.Offsets)
	restarted := inspect(t)
	require.Same(t, first.Offsets, restarted.Offsets)
	key := executableCacheKey(first.FileInfo)
	require.Equal(t, key, executableCacheKey(restarted.FileInfo))
	// A metadata change on the same inode must invalidate its offsets too.
	require.NoError(t, os.Chmod(path, 0o500))
	changed := inspect(t)
	require.NoError(t, changed.InstrumentationError)
	require.NotNil(t, changed.Offsets)
	newKey := executableCacheKey(changed.FileInfo)
	require.Equal(t, key.Dev, newKey.Dev)
	require.Equal(t, key.Ino, newKey.Ino)
	require.NotEqual(t, key.ChangeTime, newKey.ChangeTime)
	require.NotSame(t, first.Offsets, changed.Offsets)

	t.Run("proxy", func(t *testing.T) {
		ty.goOffsetsCache.Purge()
		ty.allGoFunctions = []string{"runtime.chansend1"}
		original := findProcLanguage
		t.Cleanup(func() { findProcLanguage = original })
		var pids []app.PID
		findProcLanguage = func(pid app.PID) (svc.InstrumentableType, error) {
			pids = append(pids, pid)
			return original(pid)
		}

		first := inspect(t)
		require.Nil(t, first.Offsets)
		require.ErrorContains(t, first.InstrumentationError, "identified as a Go proxy")
		key := executableCacheKey(first.FileInfo)
		result, ok := ty.goOffsetsCache.Peek(key)
		require.True(t, ok)
		require.Contains(t, result.offsets.Funcs, "runtime.chansend1")

		restarted := inspect(t)
		require.Equal(t, key, executableCacheKey(restarted.FileInfo))
		require.Nil(t, restarted.Offsets)
		require.ErrorContains(t, restarted.InstrumentationError, "identified as a Go proxy")
		after, ok := ty.goOffsetsCache.Peek(key)
		require.True(t, ok)
		require.Same(t, result.offsets, after.offsets)
		require.Equal(t, []app.PID{first.FileInfo.Pid(), restarted.FileInfo.Pid()}, pids)
	})
}

func TestNativeExecutableRestart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires procfs")
	}
	ty := newRestartTestTyper(t)
	original := findProcLanguage
	defer func() { findProcLanguage = original }()
	calls := 0
	findProcLanguage = func(pid app.PID) (svc.InstrumentableType, error) {
		calls++
		return original(pid)
	}
	for range 3 {
		result := classifyUntilExit(t, ty, osexec.Command("cat"))
		require.Equal(t, svc.InstrumentableGeneric, result.Type)
		require.NoError(t, result.InstrumentationError)
		require.Nil(t, result.Offsets)
	}
	require.Equal(t, 3, calls)
}

func newRestartTestTyper(t *testing.T) *typer {
	t.Helper()
	cache, err := lru.New[cacheKey, goInspectionResult](100)
	require.NoError(t, err)
	ty := &typer{
		cfg:            &obi.DefaultConfig,
		log:            slog.Default(),
		currentPids:    map[app.PID]*exec.FileInfo{},
		goOffsetsCache: cache,
	}
	ty.loadAllGoFunctionNames()
	return ty
}

// The child waits for EOF so discovery can inspect the live executable.
func classifyUntilExit(t *testing.T, ty *typer, cmd *osexec.Cmd) ebpf.Instrumentable {
	t.Helper()
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	defer func() {
		if cmd.ProcessState == nil {
			_ = stdin.Close()
			_ = cmd.Wait()
		}
	}()
	match := ProcessMatch{
		Process:             &services.ProcessInfo{Pid: app.PID(cmd.Process.Pid), ExePath: cmd.Path},
		LogEnricherCriteria: []services.Selector{dummyCriterion{}},
	}
	created := ty.FilterClassify([]Event[ProcessMatch]{{Type: EventCreated, Obj: match}})
	require.Len(t, created, 1)
	result := created[0].Obj
	defer result.FileInfo.ELF().Close()
	require.True(t, result.LogEnricherEnabled)
	require.NoError(t, stdin.Close())
	require.NoError(t, cmd.Wait())
	deleted := ty.FilterClassify([]Event[ProcessMatch]{{Type: EventDeleted, Obj: match}})
	require.Len(t, deleted, 1)
	require.Same(t, result.FileInfo, deleted[0].Obj.FileInfo)
	return result
}
