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

func TestSplitShellFieldsQuoting(t *testing.T) {
	tests := []struct {
		input string
		want  []string
		ok    bool
	}{
		{`a\ b`, []string{"a b"}, true},
		{`"a\"b"`, []string{`a"b`}, true},
		{"a   b", []string{"a", "b"}, true},
		{`""`, []string{""}, true},
		{`'single " quote'`, []string{`single " quote`}, true},
		{`"unterminated`, nil, false},
		{`a\`, nil, false},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			fields, ok := splitShellFields(test.input)

			assert.Equal(t, test.ok, ok)
			if test.ok {
				assert.Equal(t, test.want, fields)
			} else {
				assert.Nil(t, fields)
			}
		})
	}
}

func TestCleanValue(t *testing.T) {
	tests := map[string]string{
		"orders":     "orders",
		"  orders  ": "orders",
		"":           "",
		"   ":        "",
		"ord\x01ers": "",
		"orders\n":   "orders",
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, CleanValue(value))
		})
	}
}

func TestOptionSet(t *testing.T) {
	assert.Equal(t, map[string]struct{}{"a": {}, "b": {}}, optionSet("a", "a", "b"))
	assert.Equal(t, map[string]struct{}{}, optionSet())
}

func TestSplitList(t *testing.T) {
	tests := map[string][]string{
		"":         nil,
		"a":        {"a"},
		"a, b":     {"a", "b"},
		" a , ,b ": {"a", "b"},
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, splitList(value))
		})
	}
}

func TestValidIdentifier(t *testing.T) {
	tests := map[string]bool{
		"":     false,
		"a":    true,
		"_":    true,
		"a1":   true,
		"_1":   true,
		"1a":   false,
		"a_b":  true,
		"a-b":  false,
		"ab c": false,
		"café": true,
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, validIdentifier(value))
		})
	}
}

func TestValidModule(t *testing.T) {
	tests := map[string]bool{
		"":     false,
		"a":    true,
		"_a1":  true,
		"a.b":  true,
		"a..b": false,
		"a.":   false,
		".a":   false,
		"1a.b": false,
		"a-b":  false,
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, validModule(value))
		})
	}
}

func TestIsStrictApplicationReference(t *testing.T) {
	tests := map[string]bool{
		"":                       false,
		"app":                    false,
		"app:":                   false,
		":app":                   false,
		"app:main":               true,
		"company.orders.api:app": true,
		"_pkg._mod:_obj":         true,
		"1a:b":                   false,
		"a.b::c":                 false,
		"app:create()":           false,
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, isStrictApplicationReference(value))
		})
	}
}

func TestIsApplicationReference(t *testing.T) {
	tests := map[string]bool{
		"":                       false,
		"app":                    false,
		"app:":                   false,
		"app:main":               true,
		"company.orders.api:app": true,
		"app:main.attr":          true,
		"app:create()":           true,
		"app:create(a=1,b=2)":    true,
		"1app:main":              false,
		"app:1main":              false,
		"app:create (a=1)":       false,
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, isApplicationReference(value))
		})
	}
}

func TestFirstApplicationReference(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"no references", []string{"orders", "--app", "inventory.wsgi:"}, ""},
		{"empty", nil, ""},
		{"first wins", []string{"app:", "orders.api:app", "inventory.wsgi:application"}, "orders.api:app"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, firstApplicationReference(test.values))
		})
	}
}

func TestLastLongOptionValue(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		initial string
		want    string
	}{
		{"not found", []string{"--other", "value"}, "initial", "initial"},
		{"last wins", []string{"--target", "a", "--target", "b"}, "", "b"},
		{"attached last wins", []string{"--target", "a", "--target=attached"}, "", "attached"},
		{"separated last wins", []string{"--target=a", "--target", "b"}, "", "b"},
		{"dangling option", []string{"--target"}, "initial", "initial"},
		{"prefix mismatch", []string{"--targets=2"}, "initial", "initial"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, lastLongOptionValue(test.args, "--target", test.initial))
		})
	}
}

func TestSeparatedOptionValue(t *testing.T) {
	tests := map[string]bool{
		"app":  true,
		"-":    true,
		"-1":   true,
		"-12":  true,
		"-1.5": true,
		"-1.":  false,
		"-.5":  true,
		"-a":   false,
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, separatedOptionValue(value))
		})
	}
}

func TestSpecificModuleName(t *testing.T) {
	tests := map[string]string{
		"":         "",
		"  ":       "",
		"orders":   "orders",
		"my_api":   "my_api",
		"Main":     "",
		"API":      "",
		"worker":   "",
		"views":    "",
		".":        "",
		"..":       "",
		"-":        "",
		"__init__": "",
		"__main__": "",
	}
	for value, expected := range tests {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, expected, specificModuleName(value))
		})
	}
}

func TestTargetReference(t *testing.T) {
	tests := map[string]string{
		"":                "",
		"orders":          "orders",
		"orders.api:app":  "orders.api",
		"orders.api :app": "orders.api",
		"a:b:c":           "a",
		":app":            "",
	}
	for target, expected := range tests {
		t.Run(target, func(t *testing.T) {
			assert.Equal(t, expected, TargetReference(target))
		})
	}
}

func TestClassifyTarget(t *testing.T) {
	tests := []struct {
		target string
		kind   TargetKind
	}{
		{"", TargetNone},
		{"orders.api", TargetModule},
		{"orders.api:app", TargetModule},
		{"app.py", TargetFile},
		{"app.PY", TargetFile},
		{"src/app.py", TargetFile},
		{"/srv/app.py", TargetFile},
		{"sub/dir/main.py", TargetFile},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			assert.Equal(t, test.kind, ClassifyTarget(test.target))
		})
	}
}
