// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTargetName(t *testing.T) {
	tests := map[string]string{
		"company.orders.api:app":                 "orders",
		"orders.wsgi:application":                "orders",
		"company.orders.settings.production":     "orders",
		"company.orders.tasks":                   "orders",
		"src/orders_service.py":                  "orders_service",
		"app.main:app":                           "",
		"main.py":                                "",
		"config.settings":                        "",
		"src/orders/__init__.py":                 "",
		"company.inventory.application:create()": "inventory",
	}
	for target, expected := range tests {
		t.Run(target, func(t *testing.T) {
			assert.Equal(t, expected, TargetName(target))
		})
	}
}

func TestSplitShellFields(t *testing.T) {
	fields, ok := splitShellFields(`--chdir '/srv/orders api' --name="orders service" --workers 4`)

	assert.True(t, ok)
	assert.Equal(t, []string{"--chdir", "/srv/orders api", "--name=orders service", "--workers", "4"}, fields)

	_, ok = splitShellFields(`--chdir 'unterminated`)
	assert.False(t, ok)
}
