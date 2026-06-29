// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	obiconfig "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

var v2AppMetricsFeatureMask = export.AppO11yFeatures |
	export.FeatureApplicationRuntime

var v2NetworkMetricsFeatureMask = export.FeatureNetwork |
	export.FeatureNetworkInterZone |
	export.FeatureNetworkFlowPackets

var v2StatsMetricsFeatureMask = export.FeatureStats

// V2ToRuntime converts a hidden config v2 extension shape into an OBI runtime
// configuration. It is an internal conversion foundation and is not wired into
// runtime loading.
func V2ToRuntime(src *schema.Extension) (*obi.Config, error) {
	if err := schema.ValidateStandalone(src); err != nil {
		return nil, err
	}
	if err := validateV2RulePatterns(src.Capture.Rules); err != nil {
		return nil, err
	}

	cfg := runtimeConfigDefaults()
	applyV2Capture(&cfg, src)
	applyV2Standalone(&cfg, src)
	applyV2MetricsEnablement(&cfg, src)
	cfg.Attributes.Select.Normalize()

	return &cfg, nil
}

func runtimeConfigDefaults() obi.Config {
	cfg := obi.DefaultConfig
	if cfg.Routes != nil {
		routes := *cfg.Routes
		cfg.Routes = &routes
	}
	if cfg.NameResolver != nil {
		nameResolver := *cfg.NameResolver
		cfg.NameResolver = &nameResolver
	}
	return cfg
}

func applyV2Capture(cfg *obi.Config, src *schema.Extension) {
	applyV2Policy(cfg, src.Capture.Policy, completePolicy(src.Capture.Policy))
	applyV2Rules(cfg, src.Capture.Rules)
	applyV2Limits(cfg, src.Capture.Limits, completeLimits(src.Capture.Limits))
	applyV2Safety(cfg, src.Capture.Safety, !zeroValue(src.Capture.Safety))
	applyV2Channels(cfg, src.Capture.Channels, completeChannels(src.Capture.Channels))
	applyV2Engine(cfg, src.Capture.Engine, completeEngine(src.Capture.Engine))
	applyV2Instrumentation(cfg, src.Capture.Instrumentation)
	applyV2NetworkCapture(cfg, src.Capture.Network.Capture, completeNetworkCapture(src.Capture.Network.Capture))
	applyV2NetworkStats(cfg, src.Capture.Network.Stats, completeNetworkStats(src.Capture.Network.Stats))
	applyV2Runtimes(cfg, src.Capture.Runtimes, completeRuntimes(src.Capture.Runtimes))
	applyV2CaptureTelemetry(cfg, src.Capture.Telemetry, completeCaptureTelemetry(src.Capture.Telemetry))
}

func applyV2Policy(cfg *obi.Config, policy schema.CapturePolicy, complete bool) {
	if zeroValue(policy) && !complete {
		return
	}

	if complete || completePolicy(policy) {
		cfg.Discovery.PollInterval = policy.PollInterval.TimeDuration()
		cfg.Discovery.MinProcessAge = policy.MinProcessAge.TimeDuration()
		return
	}

	if !zeroValue(policy.PollInterval) {
		cfg.Discovery.PollInterval = policy.PollInterval.TimeDuration()
	}
	if !zeroValue(policy.MinProcessAge) {
		cfg.Discovery.MinProcessAge = policy.MinProcessAge.TimeDuration()
	}
}

type runtimeDiscoveryRules struct {
	includeGlobs                    services.GlobDefinitionCriteria
	excludeGlobs                    services.GlobDefinitionCriteria
	includeRegex                    services.RegexDefinitionCriteria
	excludeRegex                    services.RegexDefinitionCriteria
	excludeOTelInstrumentedServices bool
	defaultOTLPGRPCPort             int
}

func applyV2Rules(cfg *obi.Config, rules []schema.Rule) {
	if rules == nil {
		return
	}

	applyRuntimeDiscoveryRules(cfg, runtimeDiscoveryRulesFromV2(rules))
}

func runtimeDiscoveryRulesFromV2(rules []schema.Rule) runtimeDiscoveryRules {
	var converted runtimeDiscoveryRules
	for _, rule := range rules {
		if collectV2ExportsOTLPExclusionRule(&converted, rule) {
			continue
		}
		globSelector, regexSelector, ok := selectorFromRule(rule)
		if !ok {
			continue
		}

		switch rule.Action {
		case schema.CaptureActionInclude:
			if regexSelector != nil {
				converted.includeRegex = append(converted.includeRegex, *regexSelector)
			} else {
				converted.includeGlobs = append(converted.includeGlobs, *globSelector)
			}
		case schema.CaptureActionExclude:
			if regexSelector != nil {
				converted.excludeRegex = append(converted.excludeRegex, *regexSelector)
			} else {
				converted.excludeGlobs = append(converted.excludeGlobs, *globSelector)
			}
		}
	}
	return converted
}

func applyRuntimeDiscoveryRules(cfg *obi.Config, rules runtimeDiscoveryRules) {
	// A present v2 rules section is authoritative for runtime selector state,
	// including the default exclusions emitted by RuntimeToV2.
	cfg.Discovery.Instrument = rules.includeGlobs
	cfg.Discovery.ExcludeInstrument = rules.excludeGlobs
	cfg.Discovery.DefaultExcludeInstrument = nil
	cfg.Discovery.Services = rules.includeRegex
	cfg.Discovery.ExcludeServices = rules.excludeRegex
	cfg.Discovery.DefaultExcludeServices = nil
	cfg.Discovery.ExcludeOTelInstrumentedServices = rules.excludeOTelInstrumentedServices
	if rules.excludeOTelInstrumentedServices {
		cfg.Discovery.DefaultOtlpGRPCPort = rules.defaultOTLPGRPCPort
	}
}

// The v2 exports_otlp exclusion rule is the exported form of this runtime
// boolean/port pair, not a general selector.
func collectV2ExportsOTLPExclusionRule(rules *runtimeDiscoveryRules, rule schema.Rule) bool {
	if rule.Action != schema.CaptureActionExclude || !ruleMatchOnlyExportsOTLP(rule.Match) {
		return false
	}

	rules.excludeOTelInstrumentedServices = true
	rules.defaultOTLPGRPCPort = rule.Match.Process.ExportsOTLP.Port
	return true
}

func validateV2RulePatterns(rules []schema.Rule) error {
	for i, rule := range rules {
		path := fmt.Sprintf("capture.rules[%d].match", i)
		if err := validateV2RuleProcessGlobPatterns(path+".process", rule.Match.Process); err != nil {
			return err
		}
		if err := validateV2RuleProcessRegexPatterns(path+".process", rule.Match.Process); err != nil {
			return err
		}
		if err := validateV2RuleKubernetesGlobPatterns(path+".kubernetes", rule.Match.Kubernetes); err != nil {
			return err
		}
		if err := validateV2RuleKubernetesRegexPatterns(path+".kubernetes", rule.Match.Kubernetes); err != nil {
			return err
		}
	}
	return nil
}

func validateV2RuleProcessGlobPatterns(path string, match schema.RuleProcessMatch) error {
	if err := validateGlobAttr(path+".language_glob", match.LanguageGlob); err != nil {
		return err
	}
	if err := validateGlobAttr(path+".cmd_args_glob", match.CmdArgsGlob); err != nil {
		return err
	}
	return validateGlobAttr(path+".exe_path_glob", match.ExePathGlob)
}

func validateV2RuleProcessRegexPatterns(path string, match schema.RuleProcessMatch) error {
	if err := validateRegexpAttr(path+".language_regex", match.LanguageRegex); err != nil {
		return err
	}
	if err := validateRegexpAttr(path+".cmd_args_regex", match.CmdArgsRegex); err != nil {
		return err
	}
	return validateRegexpAttr(path+".exe_path_regex", match.ExePathRegex)
}

func validateV2RuleKubernetesGlobPatterns(path string, match schema.RuleKubernetesMatch) error {
	if err := validateGlobAttr(path+".namespace_glob", match.NamespaceGlob); err != nil {
		return err
	}
	if err := validateGlobAttrMap(path+".metadata_glob", match.MetadataGlob); err != nil {
		return err
	}
	if err := validateGlobAttrMap(path+".pod_labels", match.PodLabels); err != nil {
		return err
	}
	return validateGlobAttrMap(path+".pod_annotations", match.PodAnnotations)
}

func validateV2RuleKubernetesRegexPatterns(path string, match schema.RuleKubernetesMatch) error {
	if err := validateRegexpAttr(path+".namespace_regex", match.NamespaceRegex); err != nil {
		return err
	}
	if err := validateRegexpAttrMap(path+".metadata_regex", match.MetadataRegex); err != nil {
		return err
	}
	if err := validateRegexpAttrMap(path+".pod_labels_regex", match.PodLabelsRegex); err != nil {
		return err
	}
	return validateRegexpAttrMap(path+".pod_annotations_regex", match.PodAnnotationsRegex)
}

func validateGlobAttr(path string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	var attr services.GlobAttr
	pattern := globPattern(values)
	if err := attr.UnmarshalText([]byte(pattern)); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func validateGlobAttrMap(path string, values map[string][]string) error {
	for key, value := range values {
		if err := validateGlobAttr(fmt.Sprintf("%s[%q]", path, key), value); err != nil {
			return err
		}
	}
	return nil
}

func validateRegexpAttr(path, value string) error {
	if value == "" {
		return nil
	}
	var attr services.RegexpAttr
	if err := attr.UnmarshalText([]byte(value)); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func validateRegexpAttrMap(path string, values map[string]string) error {
	for key, value := range values {
		if err := validateRegexpAttr(fmt.Sprintf("%s[%q]", path, key), value); err != nil {
			return err
		}
	}
	return nil
}

func selectorFromRule(rule schema.Rule) (*services.GlobAttributes, *services.RegexSelector, bool) {
	if rule.Match.Process.ExportsOTLP != nil || ruleMatchEmpty(rule.Match) {
		return nil, nil, false
	}

	if ruleUsesRegex(rule.Match) {
		if ruleUsesGlob(rule.Match) {
			return nil, nil, false
		}
		selector := regexSelectorFromRule(rule)
		applyV2RegexRuleRefinement(&selector, rule.Refine)
		return nil, &selector, true
	}

	selector := globSelectorFromRule(rule)
	applyV2GlobRuleRefinement(&selector, rule.Refine)
	return &selector, nil, true
}

func ruleMatchOnlyExportsOTLP(match schema.RuleMatch) bool {
	if match.Process.ExportsOTLP == nil {
		return false
	}
	match.Process.ExportsOTLP = nil
	return ruleMatchEmpty(match)
}

func ruleUsesRegex(match schema.RuleMatch) bool {
	return match.Process.LanguageRegex != "" ||
		match.Process.CmdArgsRegex != "" ||
		match.Process.ExePathRegex != "" ||
		match.Kubernetes.NamespaceRegex != "" ||
		len(match.Kubernetes.MetadataRegex) > 0 ||
		len(match.Kubernetes.PodLabelsRegex) > 0 ||
		len(match.Kubernetes.PodAnnotationsRegex) > 0
}

func ruleUsesGlob(match schema.RuleMatch) bool {
	return len(match.Process.LanguageGlob) > 0 ||
		len(match.Process.CmdArgsGlob) > 0 ||
		len(match.Process.ExePathGlob) > 0 ||
		len(match.Kubernetes.NamespaceGlob) > 0 ||
		len(match.Kubernetes.MetadataGlob) > 0 ||
		len(match.Kubernetes.PodLabels) > 0 ||
		len(match.Kubernetes.PodAnnotations) > 0
}

func globSelectorFromRule(rule schema.Rule) services.GlobAttributes {
	match := rule.Match
	return services.GlobAttributes{
		OpenPorts:      intEnumValue(match.Process.OpenPorts),
		PIDs:           slices.Clone(match.Process.TargetPIDs),
		Languages:      globAttr(match.Process.LanguageGlob),
		CmdArgs:        globAttr(match.Process.CmdArgsGlob),
		Path:           globAttr(match.Process.ExePathGlob),
		ContainersOnly: match.Process.ContainersOnly,
		Metadata:       globMetadata(match.Kubernetes),
		PodLabels:      globAttrMap(match.Kubernetes.PodLabels),
		PodAnnotations: globAttrMap(match.Kubernetes.PodAnnotations),
	}
}

func regexSelectorFromRule(rule schema.Rule) services.RegexSelector {
	match := rule.Match
	return services.RegexSelector{
		OpenPorts:      intEnumValue(match.Process.OpenPorts),
		PIDs:           slices.Clone(match.Process.TargetPIDs),
		Languages:      regexpAttr(match.Process.LanguageRegex),
		CmdArgs:        regexpAttr(match.Process.CmdArgsRegex),
		Path:           regexpAttr(match.Process.ExePathRegex),
		ContainersOnly: match.Process.ContainersOnly,
		Metadata:       regexMetadata(match.Kubernetes),
		PodLabels:      regexpAttrMap(match.Kubernetes.PodLabelsRegex),
		PodAnnotations: regexpAttrMap(match.Kubernetes.PodAnnotationsRegex),
	}
}

func applyV2GlobRuleRefinement(selector *services.GlobAttributes, refine schema.RuleRefinement) {
	if refine.Exports != nil {
		selector.ExportModes = exportModesFromRefinement(*refine.Exports)
	}
	if refine.HTTP != nil && !zeroValue(refine.HTTP.Routes) {
		selector.Routes = &services.CustomRoutesConfig{
			Incoming: cloneStrings(refine.HTTP.Routes.Incoming.Patterns),
			Outgoing: cloneStrings(refine.HTTP.Routes.Outgoing.Patterns),
		}
	}
}

func applyV2RegexRuleRefinement(selector *services.RegexSelector, refine schema.RuleRefinement) {
	if refine.Exports != nil {
		selector.ExportModes = exportModesFromRefinement(*refine.Exports)
	}
	if refine.HTTP != nil && !zeroValue(refine.HTTP.Routes) {
		selector.Routes = &services.CustomRoutesConfig{
			Incoming: cloneStrings(refine.HTTP.Routes.Incoming.Patterns),
			Outgoing: cloneStrings(refine.HTTP.Routes.Outgoing.Patterns),
		}
	}
}

func exportModesFromRefinement(refine schema.ExportModeRefinement) services.ExportModes {
	modes := services.NewExportModes()
	if refine.Traces {
		modes.AllowTraces()
	}
	if refine.Metrics {
		modes.AllowMetrics()
	}
	return modes
}

func intEnumValue(in *services.IntEnum) services.IntEnum {
	if in == nil {
		return services.IntEnum{}
	}
	return *in
}

func globAttr(values []string) services.GlobAttr {
	switch len(values) {
	case 0:
		return services.GlobAttr{}
	default:
		return services.NewGlob(globPattern(values))
	}
}

func globPattern(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "{" + strings.Join(values, ",") + "}"
}

func globAttrMap(values map[string][]string) map[string]*services.GlobAttr {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]*services.GlobAttr, len(values))
	for key, value := range values {
		attr := globAttr(value)
		out[key] = &attr
	}
	return out
}

func globMetadata(match schema.RuleKubernetesMatch) services.MetadataGlobMap {
	out := globAttrMap(match.MetadataGlob)
	if out == nil {
		out = services.MetadataGlobMap{}
	}
	if len(match.NamespaceGlob) > 0 {
		attr := globAttr(match.NamespaceGlob)
		out[services.AttrNamespace] = &attr
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func regexpAttr(value string) services.RegexpAttr {
	if value == "" {
		return services.RegexpAttr{}
	}
	return services.NewRegexp(value)
}

func regexpAttrMap(values map[string]string) map[string]*services.RegexpAttr {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]*services.RegexpAttr, len(values))
	for key, value := range values {
		attr := regexpAttr(value)
		out[key] = &attr
	}
	return out
}

func regexMetadata(match schema.RuleKubernetesMatch) services.MetadataRegexMap {
	out := regexpAttrMap(match.MetadataRegex)
	if out == nil {
		out = services.MetadataRegexMap{}
	}
	if match.NamespaceRegex != "" {
		attr := regexpAttr(match.NamespaceRegex)
		out[services.AttrNamespace] = &attr
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func applyV2Limits(cfg *obi.Config, limits schema.CaptureLimits, complete bool) {
	if zeroValue(limits) && !complete {
		return
	}

	if complete || completeLimits(limits) {
		cfg.Attributes.MetricSpanNameAggregationLimit = limits.MetricSpanNames
		cfg.NetworkFlows.CacheMaxFlows = limits.NetworkPackets
		return
	}

	if limits.MetricSpanNames != 0 {
		cfg.Attributes.MetricSpanNameAggregationLimit = limits.MetricSpanNames
	}
	if limits.NetworkPackets != 0 {
		cfg.NetworkFlows.CacheMaxFlows = limits.NetworkPackets
	}
}

func applyV2Safety(cfg *obi.Config, safety schema.CaptureSafety, complete bool) {
	if zeroValue(safety) && !complete {
		return
	}

	if complete {
		cfg.EnforceSysCaps = safety.EnforceSystemCapabilities
		return
	}

	if safety.EnforceSystemCapabilities {
		cfg.EnforceSysCaps = true
	}
}

func applyV2Channels(cfg *obi.Config, channels schema.CaptureChannels, complete bool) {
	if zeroValue(channels) && !complete {
		return
	}

	if complete || completeChannels(channels) {
		cfg.ChannelBufferLen = channels.BufferLen
		cfg.ChannelSendTimeout = channels.SendTimeout.TimeDuration()
		cfg.ChannelSendTimeoutPanic = channels.PanicOnSendTimeout
		return
	}

	if channels.BufferLen != 0 {
		cfg.ChannelBufferLen = channels.BufferLen
	}
	if !zeroValue(channels.SendTimeout) {
		cfg.ChannelSendTimeout = channels.SendTimeout.TimeDuration()
	}
	if channels.PanicOnSendTimeout {
		cfg.ChannelSendTimeoutPanic = true
	}
}

func applyV2Engine(cfg *obi.Config, engine schema.CaptureEngine, complete bool) {
	if zeroValue(engine) && !complete {
		return
	}

	if complete || completeEngine(engine) {
		applyFullV2Engine(cfg, engine)
		return
	}

	applyPartialV2Engine(cfg, engine)
}

func applyFullV2Engine(cfg *obi.Config, engine schema.CaptureEngine) {
	cfg.EBPF.BpfDebug = engine.Debug.BPF
	cfg.EBPF.ProtocolDebug = engine.Debug.ProtocolPrint
	cfg.Discovery.BPFPidFilterOff = engine.PIDFilter.Disabled
	cfg.EBPF.WakeupLen = engine.Batching.WakeupLen
	cfg.EBPF.BatchLength = engine.Batching.BatchLength
	cfg.EBPF.BatchTimeout = engine.Batching.BatchTimeout.TimeDuration()
	cfg.EBPF.ContextPropagation = engine.Propagation.ContextPropagation
	cfg.EBPF.OverrideBPFLoopEnabled = engine.Propagation.OverrideBPFLoopEnabled
	cfg.EBPF.DisableBlackBoxCP = engine.Propagation.DisableBlackBoxCP
	cfg.EBPF.TCBackend = engine.Traffic.ControlBackend
	cfg.EBPF.HighRequestVolume = engine.Traffic.HighRequestVolume
	cfg.EBPF.ForceBPFMapReader = engine.Traffic.ForceMapReader
	cfg.EBPF.MaxTransactionTime = engine.Transactions.MaxDuration.TimeDuration()
	cfg.EBPF.MapsConfig.GlobalScaleFactor = engine.Maps.GlobalScaleFactor
	cfg.EBPF.BPFFSPath = engine.BPFFileSystem.Path
}

func applyPartialV2Engine(cfg *obi.Config, engine schema.CaptureEngine) {
	if engine.Debug.BPF {
		cfg.EBPF.BpfDebug = true
	}
	if engine.Debug.ProtocolPrint {
		cfg.EBPF.ProtocolDebug = true
	}
	if engine.PIDFilter.Disabled {
		cfg.Discovery.BPFPidFilterOff = true
	}
	if engine.Batching.WakeupLen != 0 {
		cfg.EBPF.WakeupLen = engine.Batching.WakeupLen
	}
	if engine.Batching.BatchLength != 0 {
		cfg.EBPF.BatchLength = engine.Batching.BatchLength
	}
	if !zeroValue(engine.Batching.BatchTimeout) {
		cfg.EBPF.BatchTimeout = engine.Batching.BatchTimeout.TimeDuration()
	}
	if !zeroValue(engine.Propagation.ContextPropagation) {
		cfg.EBPF.ContextPropagation = engine.Propagation.ContextPropagation
	}
	if engine.Propagation.OverrideBPFLoopEnabled {
		cfg.EBPF.OverrideBPFLoopEnabled = true
	}
	if engine.Propagation.DisableBlackBoxCP {
		cfg.EBPF.DisableBlackBoxCP = true
	}
	if !zeroValue(engine.Traffic.ControlBackend) {
		cfg.EBPF.TCBackend = engine.Traffic.ControlBackend
	}
	if engine.Traffic.HighRequestVolume {
		cfg.EBPF.HighRequestVolume = true
	}
	if !zeroValue(engine.Traffic.ForceMapReader) {
		cfg.EBPF.ForceBPFMapReader = engine.Traffic.ForceMapReader
	}
	if !zeroValue(engine.Transactions.MaxDuration) {
		cfg.EBPF.MaxTransactionTime = engine.Transactions.MaxDuration.TimeDuration()
	}
	if engine.Maps.GlobalScaleFactor != 0 {
		cfg.EBPF.MapsConfig.GlobalScaleFactor = engine.Maps.GlobalScaleFactor
	}
	if engine.BPFFileSystem.Path != "" {
		cfg.EBPF.BPFFSPath = engine.BPFFileSystem.Path
	}
}

func applyV2Instrumentation(cfg *obi.Config, instrumentation schema.Instrumentation) {
	if zeroValue(instrumentation) {
		return
	}

	complete := completeInstrumentation(instrumentation)
	if !complete {
		applyPartialV2Instrumentation(cfg, instrumentation)
		applyProtocolEnablement(cfg, instrumentation, complete)
		return
	}

	applyFullV2Instrumentation(cfg, instrumentation)
	applyProtocolEnablement(cfg, instrumentation, complete)
}

func applyFullV2Instrumentation(cfg *obi.Config, instrumentation schema.Instrumentation) {
	cfg.EBPF.TrackRequestHeaders = instrumentation.HTTP.TrackRequestHeaders
	cfg.EBPF.HTTPRequestTimeout = instrumentation.HTTP.RequestTimeout.TimeDuration()
	cfg.EBPF.BufferSizes.HTTP = instrumentation.HTTP.BufferSize

	cfg.EBPF.HeuristicSQLDetect = instrumentation.SQL.HeuristicDetect
	cfg.EBPF.BufferSizes.MySQL = instrumentation.SQL.MySQL.BufferSize
	cfg.EBPF.MySQLPreparedStatementsCacheSize = instrumentation.SQL.MySQL.PreparedStatementsCacheSize
	cfg.EBPF.BufferSizes.Postgres = instrumentation.SQL.Postgres.BufferSize
	cfg.EBPF.PostgresPreparedStatementsCacheSize = instrumentation.SQL.Postgres.PreparedStatementsCacheSize
	cfg.EBPF.BufferSizes.MSSQL = instrumentation.SQL.MSSQL.BufferSize
	cfg.EBPF.MSSQLPreparedStatementsCacheSize = instrumentation.SQL.MSSQL.PreparedStatementsCacheSize

	cfg.EBPF.RedisDBCache.Enabled = instrumentation.Redis.DBCache.Enabled
	cfg.EBPF.RedisDBCache.MaxSize = instrumentation.Redis.DBCache.MaxSize

	cfg.EBPF.BufferSizes.Kafka = instrumentation.Kafka.BufferSize
	cfg.EBPF.KafkaTopicUUIDCacheSize = instrumentation.Kafka.TopicUUIDCacheSize

	cfg.EBPF.MongoRequestsCacheSize = instrumentation.Mongo.RequestsCacheSize
	cfg.EBPF.CouchbaseDBCacheSize = instrumentation.Couchbase.DBCacheSize
	cfg.EBPF.DNSRequestTimeout = instrumentation.DNS.RequestTimeout.TimeDuration()
	cfg.EBPF.InstrumentCuda = instrumentation.GPU.EnabledMode
}

func applyPartialV2Instrumentation(cfg *obi.Config, instrumentation schema.Instrumentation) {
	if !zeroValue(instrumentation.HTTP) {
		if instrumentation.HTTP.TrackRequestHeaders {
			cfg.EBPF.TrackRequestHeaders = true
		}
		if !zeroValue(instrumentation.HTTP.RequestTimeout) {
			cfg.EBPF.HTTPRequestTimeout = instrumentation.HTTP.RequestTimeout.TimeDuration()
		}
		if instrumentation.HTTP.BufferSize != 0 {
			cfg.EBPF.BufferSizes.HTTP = instrumentation.HTTP.BufferSize
		}
	}

	if !zeroValue(instrumentation.SQL) {
		if instrumentation.SQL.HeuristicDetect {
			cfg.EBPF.HeuristicSQLDetect = true
		}
		if instrumentation.SQL.MySQL.BufferSize != 0 {
			cfg.EBPF.BufferSizes.MySQL = instrumentation.SQL.MySQL.BufferSize
		}
		if instrumentation.SQL.MySQL.PreparedStatementsCacheSize != 0 {
			cfg.EBPF.MySQLPreparedStatementsCacheSize = instrumentation.SQL.MySQL.PreparedStatementsCacheSize
		}
		if instrumentation.SQL.Postgres.BufferSize != 0 {
			cfg.EBPF.BufferSizes.Postgres = instrumentation.SQL.Postgres.BufferSize
		}
		if instrumentation.SQL.Postgres.PreparedStatementsCacheSize != 0 {
			cfg.EBPF.PostgresPreparedStatementsCacheSize = instrumentation.SQL.Postgres.PreparedStatementsCacheSize
		}
		if instrumentation.SQL.MSSQL.BufferSize != 0 {
			cfg.EBPF.BufferSizes.MSSQL = instrumentation.SQL.MSSQL.BufferSize
		}
		if instrumentation.SQL.MSSQL.PreparedStatementsCacheSize != 0 {
			cfg.EBPF.MSSQLPreparedStatementsCacheSize = instrumentation.SQL.MSSQL.PreparedStatementsCacheSize
		}
	}

	if !zeroValue(instrumentation.Redis.DBCache) {
		if instrumentation.Redis.DBCache.Enabled {
			cfg.EBPF.RedisDBCache.Enabled = true
		}
		if instrumentation.Redis.DBCache.MaxSize != 0 {
			cfg.EBPF.RedisDBCache.MaxSize = instrumentation.Redis.DBCache.MaxSize
		}
	}

	if instrumentation.Kafka.BufferSize != 0 {
		cfg.EBPF.BufferSizes.Kafka = instrumentation.Kafka.BufferSize
	}
	if instrumentation.Kafka.TopicUUIDCacheSize != 0 {
		cfg.EBPF.KafkaTopicUUIDCacheSize = instrumentation.Kafka.TopicUUIDCacheSize
	}
	if instrumentation.Mongo.RequestsCacheSize != 0 {
		cfg.EBPF.MongoRequestsCacheSize = instrumentation.Mongo.RequestsCacheSize
	}
	if instrumentation.Couchbase.DBCacheSize != 0 {
		cfg.EBPF.CouchbaseDBCacheSize = instrumentation.Couchbase.DBCacheSize
	}
	if !zeroValue(instrumentation.DNS.RequestTimeout) {
		cfg.EBPF.DNSRequestTimeout = instrumentation.DNS.RequestTimeout.TimeDuration()
	}
	if !zeroValue(instrumentation.GPU.EnabledMode) {
		cfg.EBPF.InstrumentCuda = instrumentation.GPU.EnabledMode
	}
}

func applyProtocolEnablement(cfg *obi.Config, instrumentation schema.Instrumentation, complete bool) {
	cfg.Traces.Instrumentations = applySignalEnablement(cfg.Traces.Instrumentations, instrumentation, "traces", complete)
	cfg.OTELMetrics.Instrumentations = applySignalEnablement(cfg.OTELMetrics.Instrumentations, instrumentation, "metrics", complete)
	cfg.Prometheus.Instrumentations = applySignalEnablement(cfg.Prometheus.Instrumentations, instrumentation, "metrics", complete)
}

func applySignalEnablement(
	current []instrumentations.Instrumentation,
	instrumentation schema.Instrumentation,
	signal string,
	complete bool,
) []instrumentations.Instrumentation {
	selected := map[instrumentations.Instrumentation]bool{}
	hadWildcard := false
	for _, instr := range current {
		if instr == instrumentations.InstrumentationALL {
			hadWildcard = true
			for _, candidate := range runtimeInstrumentations {
				selected[candidate] = true
			}
			continue
		}
		selected[instr] = true
	}

	for _, mapping := range protocolMappings {
		enablement := protocolEnablement(instrumentation, mapping.name)
		enabled := signalEnabled(enablement, signal)
		if !complete && !enabled {
			continue
		}
		selected[mapping.instr] = enabled
	}

	allEnabled := true
	for _, candidate := range runtimeInstrumentations {
		if !selected[candidate] {
			allEnabled = false
			break
		}
	}
	if hadWildcard && allEnabled {
		return []instrumentations.Instrumentation{instrumentations.InstrumentationALL}
	}

	out := make([]instrumentations.Instrumentation, 0, len(runtimeInstrumentations))
	for _, candidate := range runtimeInstrumentations {
		if selected[candidate] {
			out = append(out, candidate)
		}
	}
	return out
}

func applyV2NetworkCapture(cfg *obi.Config, capture schema.NetworkCapture, complete bool) {
	if zeroValue(capture) && !complete {
		return
	}

	if complete || completeNetworkCapture(capture) {
		applyFullV2NetworkCapture(cfg, capture)
		return
	}

	applyPartialV2NetworkCapture(cfg, capture)
}

func applyFullV2NetworkCapture(cfg *obi.Config, capture schema.NetworkCapture) {
	cfg.NetworkFlows.Enable = capture.Enabled
	cfg.NetworkFlows.Source = string(capture.Source)
	cfg.EBPF.BufferSizes.TCP = capture.BufferSize
	cfg.NetworkFlows.AgentIP = capture.EndpointIdentity.AgentIP
	cfg.NetworkFlows.AgentIPIface = obi.AgentTypeIface(capture.EndpointIdentity.AgentIPInterface)
	cfg.NetworkFlows.AgentIPType = string(capture.EndpointIdentity.AgentIPFamily)
	cfg.NetworkFlows.Interfaces = cloneStrings(capture.Selection.Interfaces.Include)
	cfg.NetworkFlows.ExcludeInterfaces = cloneStrings(capture.Selection.Interfaces.Exclude)
	cfg.NetworkFlows.Protocols = cloneStrings(capture.Selection.Protocols.Include)
	cfg.NetworkFlows.ExcludeProtocols = cloneStrings(capture.Selection.Protocols.Exclude)
	cfg.NetworkFlows.Direction = string(capture.Selection.Direction)
	cfg.NetworkFlows.CIDRs = cloneRuntimeCIDRDefinitions(cfg.NetworkFlows.CIDRs, capture.Selection.CIDRs)
	if filters, ok := networkFilterMap(capture.Filters); ok {
		cfg.Filters.Network = filters
	}
	cfg.NetworkFlows.CacheMaxFlows = capture.FlowLifecycle.MaxTrackedFlows
	cfg.NetworkFlows.CacheActiveTimeout = capture.FlowLifecycle.ActiveTimeout.TimeDuration()
	cfg.NetworkFlows.Deduper = string(capture.FlowLifecycle.Deduplication.Strategy)
	cfg.NetworkFlows.DeduperFCTTL = capture.FlowLifecycle.Deduplication.FirstComeTTL.TimeDuration()
	cfg.NetworkFlows.Sampling = capture.FlowLifecycle.Sampling
	cfg.NetworkFlows.GuessPorts = capture.FlowLifecycle.GuessPorts
	cfg.NetworkFlows.ListenInterfaces = string(capture.InterfaceDiscovery.Mode)
	cfg.NetworkFlows.ListenPollPeriod = capture.InterfaceDiscovery.PollInterval.TimeDuration()
	applyFullV2NetworkEnrichment(cfg, capture.Enrichment)
	cfg.NetworkFlows.Print = capture.Diagnostics.PrintFlows
}

func applyPartialV2NetworkCapture(cfg *obi.Config, capture schema.NetworkCapture) {
	if capture.Enabled {
		cfg.NetworkFlows.Enable = true
	}
	if !zeroValue(capture.Source) {
		cfg.NetworkFlows.Source = string(capture.Source)
	}
	if capture.BufferSize != 0 {
		cfg.EBPF.BufferSizes.TCP = capture.BufferSize
	}
	if capture.EndpointIdentity.AgentIP != "" {
		cfg.NetworkFlows.AgentIP = capture.EndpointIdentity.AgentIP
	}
	if capture.EndpointIdentity.AgentIPInterface != "" {
		cfg.NetworkFlows.AgentIPIface = obi.AgentTypeIface(capture.EndpointIdentity.AgentIPInterface)
	}
	if capture.EndpointIdentity.AgentIPFamily != "" {
		cfg.NetworkFlows.AgentIPType = string(capture.EndpointIdentity.AgentIPFamily)
	}
	if capture.Selection.Interfaces.Include != nil {
		cfg.NetworkFlows.Interfaces = cloneStrings(capture.Selection.Interfaces.Include)
	}
	if capture.Selection.Interfaces.Exclude != nil {
		cfg.NetworkFlows.ExcludeInterfaces = cloneStrings(capture.Selection.Interfaces.Exclude)
	}
	if capture.Selection.Protocols.Include != nil {
		cfg.NetworkFlows.Protocols = cloneStrings(capture.Selection.Protocols.Include)
	}
	if capture.Selection.Protocols.Exclude != nil {
		cfg.NetworkFlows.ExcludeProtocols = cloneStrings(capture.Selection.Protocols.Exclude)
	}
	if capture.Selection.Direction != "" {
		cfg.NetworkFlows.Direction = string(capture.Selection.Direction)
	}
	if capture.Selection.CIDRs != nil {
		cfg.NetworkFlows.CIDRs = cloneRuntimeCIDRDefinitions(cfg.NetworkFlows.CIDRs, capture.Selection.CIDRs)
	}
	if !zeroValue(capture.Filters) {
		if filters, ok := networkFilterMap(capture.Filters); ok {
			cfg.Filters.Network = filters
		}
	}
	if capture.FlowLifecycle.MaxTrackedFlows != 0 {
		cfg.NetworkFlows.CacheMaxFlows = capture.FlowLifecycle.MaxTrackedFlows
	}
	if !zeroValue(capture.FlowLifecycle.ActiveTimeout) {
		cfg.NetworkFlows.CacheActiveTimeout = capture.FlowLifecycle.ActiveTimeout.TimeDuration()
	}
	if capture.FlowLifecycle.Deduplication.Strategy != "" {
		cfg.NetworkFlows.Deduper = string(capture.FlowLifecycle.Deduplication.Strategy)
	}
	if !zeroValue(capture.FlowLifecycle.Deduplication.FirstComeTTL) {
		cfg.NetworkFlows.DeduperFCTTL = capture.FlowLifecycle.Deduplication.FirstComeTTL.TimeDuration()
	}
	if capture.FlowLifecycle.Sampling != 0 {
		cfg.NetworkFlows.Sampling = capture.FlowLifecycle.Sampling
	}
	if capture.FlowLifecycle.GuessPorts != "" {
		cfg.NetworkFlows.GuessPorts = capture.FlowLifecycle.GuessPorts
	}
	if capture.InterfaceDiscovery.Mode != "" {
		cfg.NetworkFlows.ListenInterfaces = string(capture.InterfaceDiscovery.Mode)
	}
	if !zeroValue(capture.InterfaceDiscovery.PollInterval) {
		cfg.NetworkFlows.ListenPollPeriod = capture.InterfaceDiscovery.PollInterval.TimeDuration()
	}
	if !zeroValue(capture.Enrichment) {
		applyPartialV2NetworkEnrichment(cfg, capture.Enrichment)
	}
	if capture.Diagnostics.PrintFlows {
		cfg.NetworkFlows.Print = true
	}
}

func applyFullV2NetworkEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	cfg.NetworkFlows.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	cfg.NetworkFlows.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	cfg.NetworkFlows.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	cfg.NetworkFlows.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	cfg.NetworkFlows.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	cfg.NetworkFlows.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
}

func applyPartialV2NetworkEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	if enrichment.GeoIP.IPInfo.Path != "" {
		cfg.NetworkFlows.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	}
	if enrichment.GeoIP.MaxMind.CountryPath != "" {
		cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	}
	if enrichment.GeoIP.MaxMind.ASNPath != "" {
		cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	}
	if enrichment.GeoIP.Cache.Size != 0 {
		cfg.NetworkFlows.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	}
	if !zeroValue(enrichment.GeoIP.Cache.TTL) {
		cfg.NetworkFlows.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	}
	if enrichment.ReverseDNS.Mode != "" {
		cfg.NetworkFlows.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	}
	if enrichment.ReverseDNS.Cache.Size != 0 {
		cfg.NetworkFlows.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	}
	if !zeroValue(enrichment.ReverseDNS.Cache.TTL) {
		cfg.NetworkFlows.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
	}
}

func applyV2NetworkStats(cfg *obi.Config, stats schema.NetworkStats, complete bool) {
	if zeroValue(stats) && !complete {
		return
	}

	if complete || completeNetworkStats(stats) {
		applyFullV2NetworkStats(cfg, stats)
		return
	}

	applyPartialV2NetworkStats(cfg, stats)
}

func applyFullV2NetworkStats(cfg *obi.Config, stats schema.NetworkStats) {
	cfg.Stats.AgentIP = stats.EndpointIdentity.AgentIP
	cfg.Stats.AgentIPIface = obi.AgentTypeIface(stats.EndpointIdentity.AgentIPInterface)
	cfg.Stats.AgentIPType = string(stats.EndpointIdentity.AgentIPFamily)
	cfg.Stats.CIDRs = cloneRuntimeCIDRDefinitions(cfg.Stats.CIDRs, stats.Selection.CIDRs)
	cfg.Filters.Stats = attributeFilterMap(stats.Filters.Metrics)
	applyFullV2StatsEnrichment(cfg, stats.Enrichment)
	cfg.Stats.Print = stats.Diagnostics.PrintStats
}

func applyPartialV2NetworkStats(cfg *obi.Config, stats schema.NetworkStats) {
	if stats.EndpointIdentity.AgentIP != "" {
		cfg.Stats.AgentIP = stats.EndpointIdentity.AgentIP
	}
	if stats.EndpointIdentity.AgentIPInterface != "" {
		cfg.Stats.AgentIPIface = obi.AgentTypeIface(stats.EndpointIdentity.AgentIPInterface)
	}
	if stats.EndpointIdentity.AgentIPFamily != "" {
		cfg.Stats.AgentIPType = string(stats.EndpointIdentity.AgentIPFamily)
	}
	if stats.Selection.CIDRs != nil {
		cfg.Stats.CIDRs = cloneRuntimeCIDRDefinitions(cfg.Stats.CIDRs, stats.Selection.CIDRs)
	}
	if stats.Filters.Metrics != nil {
		cfg.Filters.Stats = attributeFilterMap(stats.Filters.Metrics)
	}
	if !zeroValue(stats.Enrichment) {
		applyPartialV2StatsEnrichment(cfg, stats.Enrichment)
	}
	if stats.Diagnostics.PrintStats {
		cfg.Stats.Print = true
	}
}

func applyFullV2StatsEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	cfg.Stats.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	cfg.Stats.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	cfg.Stats.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	cfg.Stats.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	cfg.Stats.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	cfg.Stats.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	cfg.Stats.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	cfg.Stats.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
}

func applyPartialV2StatsEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	if enrichment.GeoIP.IPInfo.Path != "" {
		cfg.Stats.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	}
	if enrichment.GeoIP.MaxMind.CountryPath != "" {
		cfg.Stats.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	}
	if enrichment.GeoIP.MaxMind.ASNPath != "" {
		cfg.Stats.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	}
	if enrichment.GeoIP.Cache.Size != 0 {
		cfg.Stats.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	}
	if !zeroValue(enrichment.GeoIP.Cache.TTL) {
		cfg.Stats.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	}
	if enrichment.ReverseDNS.Mode != "" {
		cfg.Stats.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	}
	if enrichment.ReverseDNS.Cache.Size != 0 {
		cfg.Stats.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	}
	if !zeroValue(enrichment.ReverseDNS.Cache.TTL) {
		cfg.Stats.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
	}
}

func applyV2Runtimes(cfg *obi.Config, runtimes schema.CaptureRuntimes, complete bool) {
	if zeroValue(runtimes) && !complete {
		return
	}

	if complete || completeRuntimes(runtimes) {
		applyFullV2Runtimes(cfg, runtimes)
		return
	}

	applyPartialV2Runtimes(cfg, runtimes)
}

func applyFullV2Runtimes(cfg *obi.Config, runtimes schema.CaptureRuntimes) {
	cfg.Discovery.SkipGoSpecificTracers = !runtimes.Go.Enabled
	cfg.NodeJS.Enabled = runtimes.NodeJS.Enabled
	cfg.Java.Enabled = runtimes.Java.Enabled
	cfg.Java.Debug = runtimes.Java.Debug.Enabled
	cfg.Java.DebugInstrumentation = runtimes.Java.Debug.BytecodeInstrumentation
	cfg.Java.Timeout = runtimes.Java.AttachTimeout.TimeDuration()
}

func applyPartialV2Runtimes(cfg *obi.Config, runtimes schema.CaptureRuntimes) {
	if runtimes.Go.Enabled {
		cfg.Discovery.SkipGoSpecificTracers = false
	}
	if runtimes.NodeJS.Enabled {
		cfg.NodeJS.Enabled = true
	}
	if runtimes.Java.Enabled {
		cfg.Java.Enabled = true
	}
	if runtimes.Java.Debug.Enabled {
		cfg.Java.Debug = true
	}
	if runtimes.Java.Debug.BytecodeInstrumentation {
		cfg.Java.DebugInstrumentation = true
	}
	if !zeroValue(runtimes.Java.AttachTimeout) {
		cfg.Java.Timeout = runtimes.Java.AttachTimeout.TimeDuration()
	}
}

func applyV2CaptureTelemetry(cfg *obi.Config, telemetry schema.CaptureTelemetry, complete bool) {
	if zeroValue(telemetry) && !complete {
		return
	}

	if complete || completeCaptureTelemetry(telemetry) {
		applyFullV2CaptureTelemetry(cfg, telemetry)
		return
	}

	applyPartialV2CaptureTelemetry(cfg, telemetry)
}

func applyFullV2CaptureTelemetry(cfg *obi.Config, telemetry schema.CaptureTelemetry) {
	cfg.Traces.ReportersCacheLen = telemetry.Traces.ReportersCacheLen
	cfg.OTELMetrics.ReportersCacheLen = telemetry.Metrics.ReportersCacheLen
	cfg.OTELMetrics.TTL = telemetry.Metrics.TTL.TimeDuration()
}

func applyPartialV2CaptureTelemetry(cfg *obi.Config, telemetry schema.CaptureTelemetry) {
	if telemetry.Traces.ReportersCacheLen != 0 {
		cfg.Traces.ReportersCacheLen = telemetry.Traces.ReportersCacheLen
	}
	if telemetry.Metrics.ReportersCacheLen != 0 {
		cfg.OTELMetrics.ReportersCacheLen = telemetry.Metrics.ReportersCacheLen
	}
	if !zeroValue(telemetry.Metrics.TTL) {
		cfg.OTELMetrics.TTL = telemetry.Metrics.TTL.TimeDuration()
	}
}

func applyV2Standalone(cfg *obi.Config, src *schema.Extension) {
	applyV2EnrichServiceName(cfg, src.Enrich)
	applyV2Correlation(cfg, src.Correlation)
	applyV2Daemon(cfg, src.Daemon)
}

func applyV2EnrichServiceName(cfg *obi.Config, enrich *schema.Enrich) {
	if enrich == nil || zeroValue(enrich.ServiceName) {
		return
	}

	serviceName := enrich.ServiceName
	if cfg.NameResolver == nil {
		cfg.NameResolver = &transform.NameResolverConfig{}
	}

	cfg.NameResolver.Sources = cloneSources(serviceName.Sources)
	cfg.NameResolver.CacheLen = serviceName.Cache.Size
	cfg.NameResolver.CacheTTL = serviceName.Cache.TTL.TimeDuration()
	cfg.Attributes.RenameUnresolvedHosts = serviceName.UnresolvedHosts.Names.Default
	cfg.Attributes.RenameUnresolvedHostsOutgoing = serviceName.UnresolvedHosts.Names.Outgoing
	cfg.Attributes.RenameUnresolvedHostsIncoming = serviceName.UnresolvedHosts.Names.Incoming
}

func applyV2Correlation(cfg *obi.Config, correlation *schema.Correlation) {
	if correlation == nil || zeroValue(correlation.LogTraceAnnotation) {
		return
	}

	if !completeLogTraceAnnotation(correlation.LogTraceAnnotation) {
		applyPartialV2Correlation(cfg, correlation.LogTraceAnnotation)
		return
	}

	applyFullV2Correlation(cfg, correlation.LogTraceAnnotation)
}

func applyFullV2Correlation(cfg *obi.Config, logTrace schema.LogTraceAnnotation) {
	if logTrace.Enabled {
		cfg.EBPF.LogEnricher.Services = []obiconfig.LogEnricherServiceConfig{
			{Service: services.GlobDefinitionCriteria{{Path: services.NewGlob("*")}}},
		}
	} else {
		cfg.EBPF.LogEnricher.Services = nil
	}
	cfg.EBPF.LogEnricher.CacheTTL = logTrace.Cache.TTL.TimeDuration()
	cfg.EBPF.LogEnricher.CacheSize = logTrace.Cache.Size
	cfg.EBPF.LogEnricher.AsyncWriterWorkers = logTrace.AsyncWriter.Workers
	cfg.EBPF.LogEnricher.AsyncWriterChannelLen = logTrace.AsyncWriter.ChannelLen
}

func applyPartialV2Correlation(cfg *obi.Config, logTrace schema.LogTraceAnnotation) {
	if logTrace.Enabled {
		cfg.EBPF.LogEnricher.Services = []obiconfig.LogEnricherServiceConfig{
			{Service: services.GlobDefinitionCriteria{{Path: services.NewGlob("*")}}},
		}
	}
	if !zeroValue(logTrace.Cache.TTL) {
		cfg.EBPF.LogEnricher.CacheTTL = logTrace.Cache.TTL.TimeDuration()
	}
	if logTrace.Cache.Size != 0 {
		cfg.EBPF.LogEnricher.CacheSize = logTrace.Cache.Size
	}
	if logTrace.AsyncWriter.Workers != 0 {
		cfg.EBPF.LogEnricher.AsyncWriterWorkers = logTrace.AsyncWriter.Workers
	}
	if logTrace.AsyncWriter.ChannelLen != 0 {
		cfg.EBPF.LogEnricher.AsyncWriterChannelLen = logTrace.AsyncWriter.ChannelLen
	}
}

func completeLogTraceAnnotation(logTrace schema.LogTraceAnnotation) bool {
	return !zeroValue(logTrace.Cache) && !zeroValue(logTrace.AsyncWriter)
}

func applyV2Daemon(cfg *obi.Config, daemon *schema.Daemon) {
	if daemon == nil || zeroValue(*daemon) {
		return
	}

	if !completeDaemon(*daemon) {
		applyPartialV2Daemon(cfg, *daemon)
		return
	}

	applyFullV2Daemon(cfg, *daemon)
}

func applyFullV2Daemon(cfg *obi.Config, daemon schema.Daemon) {
	if !zeroValue(daemon.Logging) {
		cfg.LogLevel = obi.LogLevel(daemon.Logging.Level)
		cfg.LogConfig = obi.LogConfigOption(daemon.Logging.Format)
		cfg.TracePrinter = daemon.Logging.DebugTraceOutput
	}
	if cfg.TracePrinter == "" {
		cfg.TracePrinter = debug.TracePrinterDisabled
	}

	cfg.ProfilePort = daemon.Profiling.Port
	cfg.ShutdownTimeout = daemon.Shutdown.Timeout.TimeDuration()
	cfg.InternalMetrics.Exporter = daemon.InternalMetrics.Exporter
	cfg.InternalMetrics.Prometheus.Port = daemon.InternalMetrics.Prometheus.Port
	cfg.InternalMetrics.Prometheus.Path = daemon.InternalMetrics.Prometheus.Path
	cfg.InternalMetrics.BpfMetricScrapeInterval = daemon.InternalMetrics.BPF.ScrapeInterval.TimeDuration()

	prometheus := daemon.Telemetry.Metrics.Prometheus
	cfg.Prometheus.AllowServiceGraphSelfReferences = prometheus.AllowServiceGraphSelfReferences
	cfg.Prometheus.SpanMetricsServiceCacheSize = prometheus.SpanMetricsServiceCacheSize
	cfg.Prometheus.ExtraResourceLabels = cloneStrings(prometheus.ExtraResourceAttributes)
	cfg.Prometheus.ExtraSpanResourceLabels = cloneStrings(prometheus.ExtraSpanResourceAttributes)
}

func applyPartialV2Daemon(cfg *obi.Config, daemon schema.Daemon) {
	if !zeroValue(daemon.Logging) {
		if daemon.Logging.Level != "" {
			cfg.LogLevel = obi.LogLevel(daemon.Logging.Level)
		}
		if daemon.Logging.Format != "" {
			cfg.LogConfig = obi.LogConfigOption(daemon.Logging.Format)
		}
		if daemon.Logging.DebugTraceOutput != "" {
			cfg.TracePrinter = daemon.Logging.DebugTraceOutput
		}
	}
	if daemon.Profiling.Port != 0 {
		cfg.ProfilePort = daemon.Profiling.Port
	}
	if !zeroValue(daemon.Shutdown.Timeout) {
		cfg.ShutdownTimeout = daemon.Shutdown.Timeout.TimeDuration()
	}
	if !zeroValue(daemon.InternalMetrics) {
		if daemon.InternalMetrics.Exporter != "" {
			cfg.InternalMetrics.Exporter = daemon.InternalMetrics.Exporter
		}
		if daemon.InternalMetrics.Prometheus.Port != 0 {
			cfg.InternalMetrics.Prometheus.Port = daemon.InternalMetrics.Prometheus.Port
		}
		if daemon.InternalMetrics.Prometheus.Path != "" {
			cfg.InternalMetrics.Prometheus.Path = daemon.InternalMetrics.Prometheus.Path
		}
		if !zeroValue(daemon.InternalMetrics.BPF.ScrapeInterval) {
			cfg.InternalMetrics.BpfMetricScrapeInterval = daemon.InternalMetrics.BPF.ScrapeInterval.TimeDuration()
		}
	}

	prometheus := daemon.Telemetry.Metrics.Prometheus
	if prometheus.AllowServiceGraphSelfReferences {
		cfg.Prometheus.AllowServiceGraphSelfReferences = true
	}
	if prometheus.SpanMetricsServiceCacheSize != 0 {
		cfg.Prometheus.SpanMetricsServiceCacheSize = prometheus.SpanMetricsServiceCacheSize
	}
	if prometheus.ExtraResourceAttributes != nil {
		cfg.Prometheus.ExtraResourceLabels = cloneStrings(prometheus.ExtraResourceAttributes)
	}
	if prometheus.ExtraSpanResourceAttributes != nil {
		cfg.Prometheus.ExtraSpanResourceLabels = cloneStrings(prometheus.ExtraSpanResourceAttributes)
	}
}

func completeDaemon(daemon schema.Daemon) bool {
	return !zeroValue(daemon.Logging) &&
		!zeroValue(daemon.Shutdown) &&
		!zeroValue(daemon.InternalMetrics) &&
		!zeroValue(daemon.Telemetry)
}

func applyV2MetricsEnablement(cfg *obi.Config, src *schema.Extension) {
	appMetricsEnabled, appConfigured := appMetricsEnablement(
		src.Capture.Instrumentation,
		completeInstrumentation(src.Capture.Instrumentation),
	)
	networkConfigured := !zeroValue(src.Capture.Network.Capture)
	networkMetricsEnabled := src.Capture.Network.Capture.Enabled
	statsFeatures, statsConfigured := statsMetricsEnablement(src.Capture.Network.Stats)
	if appConfigured {
		cfg.Metrics.Features &^= v2AppMetricsFeatureMask
		if appMetricsEnabled {
			cfg.Metrics.Features |= export.FeatureApplicationRED
		}
	}
	if networkConfigured {
		cfg.Metrics.Features &^= v2NetworkMetricsFeatureMask
		if networkMetricsEnabled {
			cfg.Metrics.Features |= export.FeatureNetwork
		}
	}
	if statsConfigured {
		cfg.Metrics.Features &^= v2StatsMetricsFeatureMask
		cfg.Metrics.Features |= statsFeatures
	}
}

func appMetricsEnablement(instrumentation schema.Instrumentation, complete bool) (bool, bool) {
	if zeroValue(instrumentation) {
		return false, false
	}

	configured := complete
	enabled := false
	for _, mapping := range protocolMappings {
		enablement := protocolEnablement(instrumentation, mapping.name)
		metricsEnabled := signalEnabled(enablement, "metrics")
		if !complete && !metricsEnabled {
			continue
		}
		configured = true
		if metricsEnabled && mapping.appMetrics {
			enabled = true
		}
	}
	return enabled, configured
}

func completeInstrumentation(instrumentation schema.Instrumentation) bool {
	return !zeroValue(instrumentation.HTTP) &&
		!zeroValue(instrumentation.GRPC) &&
		!zeroValue(instrumentation.SQL) &&
		!zeroValue(instrumentation.Redis) &&
		!zeroValue(instrumentation.Kafka) &&
		!zeroValue(instrumentation.Mongo) &&
		!zeroValue(instrumentation.Couchbase) &&
		!zeroValue(instrumentation.DNS) &&
		!zeroValue(instrumentation.GPU)
}

func completePolicy(policy schema.CapturePolicy) bool {
	return !zeroValue(policy.PollInterval) &&
		!zeroValue(policy.MinProcessAge)
}

func completeLimits(limits schema.CaptureLimits) bool {
	return limits.MetricSpanNames != 0 &&
		limits.NetworkPackets != 0
}

func completeChannels(channels schema.CaptureChannels) bool {
	return channels.BufferLen != 0 &&
		!zeroValue(channels.SendTimeout)
}

func completeEngine(engine schema.CaptureEngine) bool {
	return !zeroValue(engine.Batching) &&
		!zeroValue(engine.Traffic.ControlBackend) &&
		!zeroValue(engine.Transactions.MaxDuration) &&
		engine.BPFFileSystem.Path != ""
}

func completeNetworkCapture(capture schema.NetworkCapture) bool {
	_, filtersOK := networkFilterMap(capture.Filters)
	return !zeroValue(capture.Source) &&
		!zeroValue(capture.EndpointIdentity) &&
		!zeroValue(capture.Selection) &&
		capture.Selection.CIDRs != nil &&
		filtersOK &&
		!zeroValue(capture.FlowLifecycle) &&
		!zeroValue(capture.InterfaceDiscovery) &&
		!zeroValue(capture.Enrichment)
}

func completeNetworkStats(stats schema.NetworkStats) bool {
	return stats.Features != nil &&
		!zeroValue(stats.EndpointIdentity) &&
		stats.Selection.CIDRs != nil &&
		stats.Filters.Metrics != nil &&
		!zeroValue(stats.Enrichment)
}

func completeRuntimes(runtimes schema.CaptureRuntimes) bool {
	return !zeroValue(runtimes.Java.AttachTimeout) &&
		(runtimes.Go.Enabled ||
			runtimes.NodeJS.Enabled ||
			runtimes.Java.Enabled ||
			!zeroValue(runtimes.Java.Debug))
}

func completeCaptureTelemetry(telemetry schema.CaptureTelemetry) bool {
	return !zeroValue(telemetry.Traces) &&
		!zeroValue(telemetry.Metrics)
}

func protocolEnablement(instrumentation schema.Instrumentation, name protocolName) schema.ProtocolEnablement {
	switch name {
	case protocolHTTP:
		return instrumentation.HTTP.Enabled
	case protocolGRPC:
		return instrumentation.GRPC.Enabled
	case protocolSQL:
		return instrumentation.SQL.Enabled
	case protocolRedis:
		return instrumentation.Redis.Enabled
	case protocolKafka:
		return instrumentation.Kafka.Enabled
	case protocolMongo:
		return instrumentation.Mongo.Enabled
	case protocolCouchbase:
		return instrumentation.Couchbase.Enabled
	case protocolDNS:
		return instrumentation.DNS.Enabled
	case protocolGPU:
		return instrumentation.GPU.Enabled
	default:
		return schema.ProtocolEnablement{}
	}
}

func statsMetricsEnablement(stats schema.NetworkStats) (export.Features, bool) {
	if stats.Features != nil {
		return statsFeatureMask(stats.Features), true
	}
	if stats.Enabled {
		return export.FeatureStats, true
	}
	return 0, false
}

func statsFeatureMask(features []string) export.Features {
	out := export.Features(0)
	for _, feature := range features {
		switch feature {
		case statsFeatureTCPRtt:
			out |= export.FeatureStatsTCPRtt
		case statsFeatureTCPFailedConnections:
			out |= export.FeatureStatsTCPFailedConnections
		case statsFeatureTCPRetransmits:
			out |= export.FeatureStatsTCPRetransmits
		case statsFeatureTCPIo:
			out |= export.FeatureStatsTCPIo
		}
	}
	return out
}

func signalEnabled(enablement schema.ProtocolEnablement, signal string) bool {
	switch signal {
	case "traces":
		return enablement.Traces
	case "metrics":
		return enablement.Metrics
	default:
		return false
	}
}

func zeroValue(value any) bool {
	if value == nil {
		return true
	}
	return reflect.ValueOf(value).IsZero()
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

type runtimeCIDRDefinition interface {
	~struct {
		CIDR string `yaml:"cidr" json:"cidr"`
		Name string `yaml:"name" json:"name"`
	}
}

type runtimeCIDRDefinitionValue struct {
	CIDR string `yaml:"cidr" json:"cidr"`
	Name string `yaml:"name" json:"name"`
}

func cloneRuntimeCIDRDefinitions[T runtimeCIDRDefinition](_ []T, definitions schema.CIDRDefinitions) []T {
	if definitions == nil {
		return nil
	}
	out := make([]T, 0, len(definitions))
	for _, definition := range definitions {
		out = append(out, T(runtimeCIDRDefinitionValue{
			CIDR: definition.CIDR,
			Name: definition.Name,
		}))
	}
	return out
}

func networkFilterMap(filters schema.SignalFilters) (filter.AttributeFamilyConfig, bool) {
	if filters.Traces == nil || filters.Metrics == nil {
		return nil, false
	}
	if !reflect.DeepEqual(filters.Traces, filters.Metrics) {
		return nil, false
	}
	return attributeFilterMap(filters.Traces), true
}

func attributeFilterMap(in schema.AttributeFilters) filter.AttributeFamilyConfig {
	if len(in) == 0 {
		return nil
	}
	out := make(filter.AttributeFamilyConfig, len(in))
	for key, def := range in {
		out[key] = filter.MatchDefinition{
			Match:         def.Match,
			NotMatch:      def.NotMatch,
			Equals:        def.Equals,
			NotEquals:     def.NotEquals,
			GreaterEquals: def.GreaterEquals,
			GreaterThan:   def.GreaterThan,
			LessEquals:    def.LessEquals,
			LessThan:      def.LessThan,
		}
	}
	return out
}

func cloneSources(values []transform.Source) []transform.Source {
	if values == nil {
		return nil
	}
	return append([]transform.Source(nil), values...)
}
