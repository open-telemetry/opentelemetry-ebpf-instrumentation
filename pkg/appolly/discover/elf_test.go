// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"reflect"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestSetServiceEnvVariables(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		k8sEnabled bool
		expectName string
		expectNS   string
	}{
		{
			name:       "OTEL_SERVICE_NAME present, k8s disabled",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service"},
			k8sEnabled: false,
			expectName: "my-service",
		},
		{
			name:       "OTEL_SERVICE_NAME present, k8s enabled",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service"},
			k8sEnabled: true,
			expectName: "",
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc"},
			k8sEnabled: false,
			expectName: "otel-svc",
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc"},
			k8sEnabled: true,
			expectName: "",
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=otel-ns"},
			k8sEnabled: false,
			expectNS:   "otel-ns",
		},
		{
			name:       "No relevant env vars",
			envVars:    map[string]string{"FOO": "BAR"},
			k8sEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := svc.Attrs{}
			s = setServiceEnvVariables(s, tt.envVars, tt.k8sEnabled)
			if got := s.UID.Name; got != tt.expectName {
				t.Errorf("UID.Name = %q, want %q", got, tt.expectName)
			}
			if got := s.UID.Namespace; got != tt.expectNS {
				t.Errorf("UID.Namespace = %q, want %q", got, tt.expectNS)
			}
			if !reflect.DeepEqual(s.EnvVars, tt.envVars) {
				t.Errorf("EnvVars = %#v, want %#v", s.EnvVars, tt.envVars)
			}
		})
	}
}
