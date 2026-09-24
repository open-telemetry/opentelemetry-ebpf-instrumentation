// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLaravelAPIPrefix(t *testing.T) {
	tests := []struct {
		name      string
		bootstrap string
		want      laravelAPIPrefix
	}{
		{name: "missing bootstrap"},
		{
			name: "default prefix",
			bootstrap: `<?php
                Application::configure()->withRouting(
                    api: __DIR__.'/../routes/api.php',
                );
            `,
			want: laravelAPIPrefix{value: "api"},
		},
		{
			name: "custom prefix",
			bootstrap: `<?php
                Application::configure()->withRouting(
                    api: __DIR__.'/../routes/api.php',
                    apiPrefix: 'v2',
                );
            `,
			want: laravelAPIPrefix{value: "v2"},
		},
		{
			name: "empty literal prefix",
			bootstrap: `<?php
                Application::configure()->withRouting(
                    api: __DIR__.'/../routes/api.php',
                    apiPrefix: '',
                );
            `,
		},
		{
			name: "no API route file",
			bootstrap: `<?php
                Application::configure()->withRouting(
                    web: __DIR__.'/../routes/web.php',
                );
			`,
		},
		{
			name:      "no routing configuration",
			bootstrap: `<?php return Application::configure();`,
		},
		{
			name: "dynamic prefix is unresolved",
			bootstrap: `<?php
                Application::configure()->withRouting(
                    api: __DIR__.'/../routes/api.php',
                    apiPrefix: configuredPrefix(),
                );
            `,
			want: laravelAPIPrefix{unresolved: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.bootstrap != "" {
				writeSymfonyTestFile(t, root, "bootstrap/app.php", test.bootstrap)
			}

			assert.Equal(t, test.want, readLaravelAPIPrefix(root))
		})
	}
}

func TestHasLaravelAPIRouteFile(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
		want      bool
	}{
		{name: "directory expression", arguments: `api: __DIR__.'/../routes/api.php'`, want: true},
		{name: "base path expression", arguments: `api: base_path('routes/api.php')`, want: true},
		{name: "array of route files", arguments: `api: [__DIR__.'/routes/admin.php', __DIR__.'/routes/api.php']`, want: true},
		{name: "missing API argument", arguments: `web: __DIR__.'/../routes/web.php'`},
		{name: "different PHP file", arguments: `api: __DIR__.'/../routes/admin.php'`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := callArguments(lexPHP([]byte("withRouting("+test.arguments+")")), 1)

			assert.Equal(t, test.want, hasLaravelAPIRouteFile(arguments))
		})
	}
}

func TestNamedLiteralArgument(t *testing.T) {
	arguments := callArguments(lexPHP([]byte(`call(path: '/users', dynamic: $path, list: ['/one'])`)), 1)

	path, ok := namedLiteralArgument(arguments, "path")
	assert.True(t, ok)
	assert.Equal(t, "/users", path)

	for _, name := range []string{"PATH", "missing", "dynamic", "list"} {
		path, ok = namedLiteralArgument(arguments, name)
		assert.False(t, ok, name)
		assert.Empty(t, path, name)
	}
}

func TestNamedArgument(t *testing.T) {
	arguments := callArguments(lexPHP([]byte(`call(first: '/one', second: build('/two'), 'positional')`)), 1)

	argument, ok := namedArgument(arguments, "second")
	assert.True(t, ok)
	assert.Equal(t, []string{"build", "(", "/two", ")"}, singleTokenValues(argument))

	for _, name := range []string{"SECOND", "missing"} {
		argument, ok = namedArgument(arguments, name)
		assert.False(t, ok, name)
		assert.Nil(t, argument, name)
	}

	invalidArguments := callArguments(lexPHP([]byte(`call(first => '/one')`)), 1)
	argument, ok = namedArgument(invalidArguments, "first")
	assert.False(t, ok)
	assert.Nil(t, argument)
}

func singleTokenValues(tokens []token) []string {
	values := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		values = append(values, tok.value)
	}
	return values
}
