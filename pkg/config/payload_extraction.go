// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

type PayloadExtraction struct {
	HTTP HTTPConfig `yaml:"http"`
}

func (p PayloadExtraction) Enabled() bool {
	return p.HTTP.GraphQL.Enabled || p.HTTP.Elasticsearch.Enabled
}

type HTTPConfig struct {
	// GraphQL payload extraction and parsing
	GraphQL GraphQLConfig `yaml:"graphql"`
	// Elasticsearch payload extraction and parsing
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
}

type GraphQLConfig struct {
	// Enable GraphQL payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_GRAPHQL_ENABLED"  validate:"boolean"`
}

type ElasticsearchConfig struct {
	// Enable Elasticsearch payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_ELASTICSEARCH_ENABLED" validate:"boolean"`
}
