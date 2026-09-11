// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadDotEnvAppName(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     string
	}{
		{name: "empty"},
		{name: "unquoted", contents: "APP_NAME=Orders API\n", want: "Orders API"},
		{name: "quoted", contents: "APP_NAME='Orders API'\n", want: "Orders API"},
		{name: "spaces around key", contents: "  APP_NAME = Orders API  \r\n", want: "Orders API"},
		{name: "comments and unrelated assignments", contents: "\n# comment\nOTHER=value\nAPP_NAME=Orders\n", want: "Orders"},
		{name: "hash without separating whitespace", contents: "APP_NAME=Orders#blue\n", want: "Orders#blue"},
		{name: "inline comment", contents: "APP_NAME=Orders API # production\n", want: "Orders API"},
		{name: "invalid assignment followed by valid one", contents: "APP_NAME=${BASE_NAME}\nAPP_NAME=Orders\n", want: "Orders"},
		{name: "comment value followed by valid one", contents: "APP_NAME= # disabled\nAPP_NAME=Orders\n", want: "Orders"},
		{name: "wrong key", contents: "APPLICATION_NAME=Orders\n"},
		{name: "missing equals", contents: "APP_NAME Orders\n"},
		{name: "empty value", contents: "APP_NAME=\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".env")
			require.NoError(t, os.WriteFile(path, []byte(test.contents), 0o600))

			assert.Equal(t, test.want, readDotEnvAppName(path))
		})
	}

	t.Run("missing", func(t *testing.T) {
		assert.Empty(t, readDotEnvAppName(filepath.Join(t.TempDir(), ".env")))
	})

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".env")
		require.NoError(t, os.WriteFile(path, make([]byte, maxDotEnvBytes+1), 0o600))

		assert.Empty(t, readDotEnvAppName(path))
	})

	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "values.env")
		path := filepath.Join(dir, ".env")
		require.NoError(t, os.WriteFile(target, []byte("APP_NAME=Orders\n"), 0o600))
		require.NoError(t, os.Symlink(target, path))

		assert.Empty(t, readDotEnvAppName(path))
	})
}

func TestLiteralDotEnvValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		valid bool
	}{
		{name: "plain", value: "Orders API", want: "Orders API", valid: true},
		{name: "trimmed", value: "  Orders API  ", want: "Orders API", valid: true},
		{name: "single quoted", value: "'Orders API'", want: "Orders API", valid: true},
		{name: "double quoted", value: `"Orders API"`, want: "Orders API", valid: true},
		{name: "inline comment", value: "Orders API # production", want: "Orders API", valid: true},
		{name: "tab before comment", value: "Orders API\t# production", want: "Orders API", valid: true},
		{name: "hash is literal without whitespace", value: "Orders#production", want: "Orders#production", valid: true},
		{name: "empty"},
		{name: "whitespace", value: " \t "},
		{name: "variable", value: "$APP"},
		{name: "embedded variable", value: "Orders-${ENV}"},
		{name: "comment leaves empty value", value: " # comment"},
		{name: "unterminated quote", value: "'Orders"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, valid := literalDotEnvValue(test.value)
			assert.Equal(t, test.want, value)
			assert.Equal(t, test.valid, valid)
		})
	}
}

func TestQuotedDotEnvValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		quote byte
		want  string
		valid bool
	}{
		{name: "single quoted", value: "'Orders API'", quote: '\'', want: "Orders API", valid: true},
		{name: "double quoted", value: `"Orders API"`, quote: '"', want: "Orders API", valid: true},
		{name: "empty quoted value", value: `""`, quote: '"', valid: true},
		{name: "escaped quote", value: `"Orders \"API\""`, quote: '"', want: `Orders "API"`, valid: true},
		{name: "escaped slash", value: `"Orders\\API"`, quote: '"', want: `Orders\API`, valid: true},
		{name: "unknown escape is preserved", value: `"Orders\qAPI"`, quote: '"', want: `Orders\qAPI`, valid: true},
		{name: "comment after quote", value: `"Orders" # production`, quote: '"', want: "Orders", valid: true},
		{name: "hash immediately after quote", value: `"Orders"#production`, quote: '"', want: "Orders", valid: true},
		{name: "invalid suffix", value: `"Orders" production`, quote: '"'},
		{name: "variable", value: `"${APP_NAME}"`, quote: '"'},
		{name: "unterminated", value: `"Orders`, quote: '"'},
		{name: "trailing slash", value: `"Orders\`, quote: '"'},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, valid := quotedDotEnvValue(test.value, test.quote)
			assert.Equal(t, test.want, value)
			assert.Equal(t, test.valid, valid)
		})
	}
}
