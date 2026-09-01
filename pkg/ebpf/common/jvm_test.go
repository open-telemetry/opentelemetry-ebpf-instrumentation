// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestDecorateJVMRuntimeEvent(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "jvm-svc"},
		SDKLanguage: svc.InstrumentableJava,
	}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}
	event := jvmruntime.JVMRuntimeEvent{PID: 55, PIDNamespaceID: 99}

	assert.True(t, DecorateJVMRuntimeEvent(filter, &event))
	assert.Equal(t, service, event.Service)
}

func TestDecorateJVMRuntimeEventRejectsNonJavaService(t *testing.T) {
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {
			55: {
				UID:         svc.UID{Name: "go-svc"},
				SDKLanguage: svc.InstrumentableGolang,
			},
		},
	}}
	event := jvmruntime.JVMRuntimeEvent{PID: 55, PIDNamespaceID: 99}

	assert.False(t, DecorateJVMRuntimeEvent(filter, &event))
}
