// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

type Feature string

const (
	FeatureNetwork          Feature = "network"
	FeatureNetworkInterZone Feature = "network_inter_zone"
	FeatureApplication      Feature = "application"
	FeatureSpan             Feature = "application_span"
	FeatureSpanOTel         Feature = "application_span_otel"
	FeatureSpanSizes        Feature = "application_span_sizes"
	FeatureGraph            Feature = "application_service_graph"
	FeatureProcess          Feature = "application_process"
	FeatureApplicationHost  Feature = "application_host"
	FeatureEBPF             Feature = "ebpf"
)
