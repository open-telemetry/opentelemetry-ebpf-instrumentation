// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectProject(t *testing.T) {
	t.Run("no project metadata", func(t *testing.T) {
		dir := t.TempDir()

		metadata, found := inspectProject(dir)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, metadata)
	})

	t.Run("composer json only", func(t *testing.T) {
		dir := t.TempDir()
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{"name":"acme/orders","version":"1.2.3"}`))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, name: "acme/orders", version: "1.2.3"}, metadata)
	})

	t.Run("installed metadata only", func(t *testing.T) {
		dir := t.TempDir()
		writePHPFile(t, filepath.Join(dir, "vendor", "composer", "installed.php"), installedPHP("acme/orders", "2.0.0"))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, name: "acme/orders", version: "2.0.0"}, metadata)
	})

	t.Run("installed metadata takes precedence", func(t *testing.T) {
		dir := t.TempDir()
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{"name":"fallback/name","version":"1.0.0"}`))
		writePHPFile(t, filepath.Join(dir, "vendor", "composer", "installed.php"), installedPHP("installed/name", "2.0.0"))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, name: "installed/name", version: "2.0.0"}, metadata)
	})

	t.Run("composer json fills invalid installed fields", func(t *testing.T) {
		dir := t.TempDir()
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{"name":"fallback/name","version":"1.0.0"}`))
		writePHPFile(t, filepath.Join(dir, "vendor", "composer", "installed.php"), installedPHP(
			composerRootPlaceholder,
			composerVersionPlaceholder,
		))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, name: "fallback/name", version: "1.0.0"}, metadata)
	})

	t.Run("empty composer document is still a project boundary", func(t *testing.T) {
		dir := t.TempDir()
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{}`))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir}, metadata)
	})

	t.Run("Symfony template uses project directory fallback", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "my_app")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{
            "name":"symfony/skeleton",
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, fallbackName: "my_app"}, metadata)
	})

	t.Run("unnamed Symfony project uses project directory fallback", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "my_app")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, fallbackName: "my_app"}, metadata)
	})

	t.Run("custom Composer name wins for Symfony", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "my_app")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{
            "name":"acme/orders",
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))
		writePHPFile(t, filepath.Join(dir, "vendor", "composer", "installed.php"), installedPHP(
			"symfony/skeleton",
			composerVersionPlaceholder,
		))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, name: "acme/orders", fallbackName: "my_app"}, metadata)
	})

	t.Run("template-like name is unchanged without Symfony confirmation", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "my_app")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{"name":"symfony/skeleton"}`))

		metadata, found := inspectProject(dir)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, name: "symfony/skeleton"}, metadata)
	})
}

func TestReadComposerJSON(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     composerMetadata
		found    bool
	}{
		{name: "valid", contents: `{"name":"acme/orders","version":"1.2.3"}`, want: composerMetadata{name: "acme/orders", version: "1.2.3"}, found: true},
		{name: "missing fields", contents: `{}`, found: true},
		{name: "unknown fields", contents: `{"description":"service"}`, found: true},
		{name: "non-string fields are ignored", contents: `{"name":42,"version":true}`, found: true},
		{name: "malformed", contents: `{"name":`, found: false},
		{name: "null document", contents: `null`, found: false},
		{name: "array document", contents: `[]`, found: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "composer.json")
			require.NoError(t, os.WriteFile(path, []byte(test.contents), 0o600))

			metadata, found := readComposerJSON(path)

			assert.Equal(t, test.found, found)
			assert.Equal(t, test.want, metadata)
		})
	}

	t.Run("missing", func(t *testing.T) {
		metadata, found := readComposerJSON(filepath.Join(t.TempDir(), "composer.json"))

		assert.False(t, found)
		assert.Equal(t, composerMetadata{}, metadata)
	})

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "composer.json")
		require.NoError(t, os.WriteFile(path, make([]byte, maxComposerJSONBytes+1), 0o600))

		metadata, found := readComposerJSON(path)

		assert.False(t, found)
		assert.Equal(t, composerMetadata{}, metadata)
	})

	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		path := filepath.Join(dir, "composer.json")
		require.NoError(t, os.WriteFile(target, []byte(`{"name":"acme/orders"}`), 0o600))
		require.NoError(t, os.Symlink(target, path))

		metadata, found := readComposerJSON(path)

		assert.False(t, found)
		assert.Equal(t, composerMetadata{}, metadata)
	})
}

func TestReadInstalledPHP(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     composerMetadata
		found    bool
	}{
		{
			name: "long array syntax",
			contents: `<?php return array(
    'root' => array(
        'name' => 'acme/orders',
        'pretty_version' => '1.2.3',
    ),
    'versions' => array(),
);`,
			want:  composerMetadata{name: "acme/orders", version: "1.2.3"},
			found: true,
		},
		{
			name: "short array and double quoted keys",
			contents: `<?php return [
    "root" => [
        'name' => 'acme\\orders\'api',
        'pretty_version' => 'dev-main\\branch',
    ],
    "versions" => [],
];`,
			want:  composerMetadata{name: `acme\orders'api`, version: `dev-main\branch`},
			found: true,
		},
		{
			name: "version package fields are excluded",
			contents: `<?php return [
    'root' => ['name' => 'root/not-line-oriented'],
    'versions' => [
        'acme/dependency' => [
            'name' => 'acme/dependency',
            'pretty_version' => '9.9.9',
        ],
    ],
];`,
			found: true,
		},
		{name: "root without fields", contents: `<?php return ['root' => [], 'versions' => []];`, found: true},
		{name: "missing root", contents: `<?php return ['versions' => []];`},
		{name: "missing versions", contents: `<?php return ['root' => []];`},
		{name: "malformed text", contents: `not PHP`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "installed.php")
			require.NoError(t, os.WriteFile(path, []byte(test.contents), 0o600))

			metadata, found := readInstalledPHP(path)

			assert.Equal(t, test.found, found)
			assert.Equal(t, test.want, metadata)
		})
	}

	t.Run("missing", func(t *testing.T) {
		metadata, found := readInstalledPHP(filepath.Join(t.TempDir(), "installed.php"))

		assert.False(t, found)
		assert.Equal(t, composerMetadata{}, metadata)
	})
}

func TestInstalledField(t *testing.T) {
	pattern := regexp.MustCompile(`value='((?:\\.|[^'\\])*)'`)

	assert.Equal(t, `acme\orders'api`, installedField([]byte(`value='acme\\orders\'api'`), pattern))
	assert.Empty(t, installedField([]byte("other='value'"), pattern))
	assert.Empty(t, installedField([]byte("value='one' value='two'"), regexp.MustCompile(`(one)(two)`)))
}

func TestUnescapePHPString(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty"},
		{name: "plain", value: "acme/orders", want: "acme/orders"},
		{name: "escaped slash", value: `acme\\orders`, want: `acme\orders`},
		{name: "escaped quote", value: `orders\'api`, want: "orders'api"},
		{name: "both escapes", value: `acme\\payments\'api`, want: `acme\payments'api`},
		{name: "unknown escape preserved", value: `acme\qorders`, want: `acme\qorders`},
		{name: "trailing slash preserved", value: `acme\`, want: `acme\`},
		{name: "consecutive escapes", value: `\\\'`, want: `\'`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, unescapePHPString(test.value))
		})
	}
}

func TestComposerName(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		valid bool
	}{
		{name: "plain", value: "acme/orders", want: "acme/orders", valid: true},
		{name: "trimmed", value: "  orders  ", want: "orders", valid: true},
		{name: "placeholder", value: "  " + composerRootPlaceholder + "  "},
		{name: "empty"},
		{name: "control character", value: "orders\napi"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, valid := composerName(test.value)
			assert.Equal(t, test.want, value)
			assert.Equal(t, test.valid, valid)
		})
	}
}

func TestComposerVersion(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		valid bool
	}{
		{name: "semantic version", value: "1.2.3", want: "1.2.3", valid: true},
		{name: "development version", value: " dev-main ", want: "dev-main", valid: true},
		{name: "placeholder", value: "  " + composerVersionPlaceholder + "  "},
		{name: "empty"},
		{name: "control character", value: "1.2.3\n", want: "1.2.3", valid: true},
		{name: "embedded control character", value: "1.2\n.3"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, valid := composerVersion(test.value)
			assert.Equal(t, test.want, value)
			assert.Equal(t, test.valid, valid)
		})
	}
}
