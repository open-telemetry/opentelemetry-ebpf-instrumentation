// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
)

func TestConnectionInfoStoreKeepsObservedEdgesAliveUntilTTL(t *testing.T) {
	now := time.Unix(100, 0)
	store := newConnectionInfoStore(time.Minute)
	edge := attribute.NewSet(attribute.String("client", "frontend"), attribute.String("server", "catalog"))

	store.observe(edge, now)
	assert.Equal(t, []attribute.Set{edge}, store.active(now.Add(59*time.Second)))

	store.observe(edge, now.Add(59*time.Second))
	assert.Equal(t, []attribute.Set{edge}, store.active(now.Add(time.Minute)))
	assert.Empty(t, store.active(now.Add(119*time.Second)))
}
