// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumentations

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInstrumentationSelection(t *testing.T) {
	is := NewInstrumentationSelection([]Instrumentation{InstrumentationHTTP, InstrumentationSQL, InstrumentationRedis})
	assert.True(t, is.HTTPEnabled())
	assert.True(t, is.SQLEnabled())
	assert.True(t, is.DBEnabled())
	assert.True(t, is.RedisEnabled())
	assert.False(t, is.GRPCEnabled())
	assert.False(t, is.KafkaEnabled())
	assert.False(t, is.MQTTEnabled())
	assert.False(t, is.MQEnabled())

	is = NewInstrumentationSelection([]Instrumentation{InstrumentationGRPC, InstrumentationKafka})
	assert.False(t, is.HTTPEnabled())
	assert.False(t, is.SQLEnabled())
	assert.False(t, is.DBEnabled())
	assert.False(t, is.RedisEnabled())
	assert.True(t, is.GRPCEnabled())
	assert.True(t, is.KafkaEnabled())
	assert.False(t, is.MQTTEnabled())
	assert.True(t, is.MQEnabled())

	// MQTT only - MQEnabled should be true
	is = NewInstrumentationSelection([]Instrumentation{InstrumentationMQTT})
	assert.False(t, is.KafkaEnabled())
	assert.True(t, is.MQTTEnabled())
	assert.True(t, is.MQEnabled())
}

func TestInstrumentationSelection_All(t *testing.T) {
	is := NewInstrumentationSelection([]Instrumentation{InstrumentationALL})
	assert.True(t, is.HTTPEnabled())
	assert.True(t, is.SQLEnabled())
	assert.True(t, is.DBEnabled())
	assert.True(t, is.RedisEnabled())
	assert.True(t, is.GRPCEnabled())
	assert.True(t, is.KafkaEnabled())
	assert.True(t, is.MQTTEnabled())
	assert.True(t, is.MQEnabled())
}

func TestInstrumentationSelection_None(t *testing.T) {
	is := NewInstrumentationSelection(nil)
	assert.False(t, is.HTTPEnabled())
	assert.False(t, is.SQLEnabled())
	assert.False(t, is.DBEnabled())
	assert.False(t, is.RedisEnabled())
	assert.False(t, is.GRPCEnabled())
	assert.False(t, is.KafkaEnabled())
	assert.False(t, is.MQTTEnabled())
	assert.False(t, is.MQEnabled())
}
