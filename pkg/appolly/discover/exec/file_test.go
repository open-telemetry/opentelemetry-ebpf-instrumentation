// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"os"
	"reflect"
	"testing"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestInstallProcessRootPreservesExactOwnership(t *testing.T) {
	first, err := os.CreateTemp(t.TempDir(), "process-root-first-*")
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.CreateTemp(t.TempDir(), "process-root-second-*")
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	fileInfo := New(Init{ProcessRoot: first})

	if fileInfo.InstallProcessRoot(second) {
		t.Fatal("InstallProcessRoot replaced an owned process root")
	}
	if got := fileInfo.TakeProcessRootIf(second); got != nil {
		t.Fatal("TakeProcessRootIf removed a different owner's process root")
	}
	if got := fileInfo.TakeProcessRootIf(first); got != first {
		t.Fatal("TakeProcessRootIf did not return the exact installed process root")
	}
	if !fileInfo.InstallProcessRoot(second) {
		t.Fatal("InstallProcessRoot rejected an empty process-root slot")
	}
	if got := fileInfo.TakeProcessRoot(); got != second {
		t.Fatal("TakeProcessRoot did not return the newly installed process root")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyEnvVariables(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		expectName string
		expectNS   string
		expectMeta map[attr.Name]string
	}{
		{
			name:       "OTEL_SERVICE_NAME present, but also name is in the OTEL_RESOURCE_ATTRIBUTES",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service", "OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc,label1=1,label2=2"},
			expectName: "my-service",
			expectMeta: map[attr.Name]string{"label1": "1", "label2": "2", "service.name": "otel-svc"},
		},
		{
			name:       "OTEL_SERVICE_NAME present",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service"},
			expectName: "my-service",
			expectNS:   "",
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc"},
			expectName: "otel-svc",
			expectMeta: map[attr.Name]string{"service.name": "otel-svc"},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name and service.namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc,service.namespace=ns1"},
			expectName: "otel-svc",
			expectNS:   "ns1",
			expectMeta: map[attr.Name]string{"service.name": "otel-svc", "service.namespace": "ns1"},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=otel-ns"},
			expectNS:   "otel-ns",
			expectMeta: map[attr.Name]string{"service.namespace": "otel-ns"},
		},
		{
			name:       "No relevant env vars",
			envVars:    map[string]string{"FOO": "BAR"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "Improper resource attributes, no key - value pairs",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace,otel-ns"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "Unresolved values in name and namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=${test-ns},service.name=$(otel-ns)"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name: "Pre-set metadata is preserved over env resource attributes",
			envVars: map[string]string{
				"OTEL_RESOURCE_ATTRIBUTES": "deployment.environment=prod,custom.attr=from-env",
			},
			expectMeta: map[attr.Name]string{
				"deployment.environment": "staging",
				"custom.attr":            "from-env",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := New(Init{})
			if tt.name == "Pre-set metadata is preserved over env resource attributes" {
				fi.SetMetadata(map[attr.Name]string{
					"deployment.environment": "staging",
				})
			}
			fi.ApplyEnvVariables(tt.envVars)
			snap := fi.ServiceAttrs()
			if got := snap.UID.Name; got != tt.expectName {
				t.Errorf("UID.Name = %q, want %q", got, tt.expectName)
			}
			if got := snap.UID.Namespace; got != tt.expectNS {
				t.Errorf("UID.Namespace = %q, want %q", got, tt.expectNS)
			}
			if !reflect.DeepEqual(snap.EnvVars, tt.envVars) {
				t.Errorf("EnvVars = %#v, want %#v", snap.EnvVars, tt.envVars)
			}
			if !reflect.DeepEqual(snap.Metadata, tt.expectMeta) {
				t.Errorf("Metadata = %#v, want %#v", snap.Metadata, tt.expectMeta)
			}
		})
	}
}
