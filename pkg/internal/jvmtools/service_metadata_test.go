// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmtools

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestResolveServiceMetadata(t *testing.T) {
	t.Run("Spring Boot resource wins and manifest supplies version", func(t *testing.T) {
		root := t.TempDir()
		archivePath := filepath.Join(root, "app", "orders-1.2.3.jar")
		writeArchive(t, archivePath, map[string]string{
			"BOOT-INF/classes/application.properties": "spring.application.name=${app.name}\n",
			"META-INF/MANIFEST.MF": strings.Join([]string{
				"Manifest-Version: 1.0",
				"Implementation-Title: manifest-orders",
				"Implementation-Version: 1.2.3",
				"",
			}, "\r\n"),
		})
		fileInfo := mockJavaProcess(t, root, []string{"-jar", "/app/orders-1.2.3.jar"}, map[string]string{
			"APP_NAME": "spring-orders",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "spring-orders", service.UID.Name)
		assert.True(t, service.AutoName())
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})

	t.Run("manifest title wins over jar name", func(t *testing.T) {
		root := t.TempDir()
		archivePath := filepath.Join(root, "app", "orders-1.2.3.jar")
		writeArchive(t, archivePath, map[string]string{
			"META-INF/MANIFEST.MF": "Implementation-Title: Orders Service\r\nImplementation-Version: 2.0\r\n\r\n",
		})
		fileInfo := mockJavaProcess(t, root, []string{"-jar", "/app/orders-1.2.3.jar"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "Orders Service", service.UID.Name)
		assert.Equal(t, "2.0", service.Metadata[serviceVersion])
	})

	t.Run("explicit name still allows manifest version", func(t *testing.T) {
		root := t.TempDir()
		archivePath := filepath.Join(root, "app", "orders.jar")
		writeArchive(t, archivePath, map[string]string{
			"META-INF/MANIFEST.MF": "Implementation-Title: manifest-orders\r\nImplementation-Version: 2.0\r\n\r\n",
		})
		fileInfo := mockJavaProcess(t, root, []string{"-jar", "/app/orders.jar"}, nil)
		fileInfo.SetUID(svc.UID{Name: "explicit-orders"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "explicit-orders", service.UID.Name)
		assert.False(t, service.AutoName())
		assert.Equal(t, "2.0", service.Metadata[serviceVersion])
	})

	t.Run("explicit name and version skip process inspection", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("must not inspect")
		fileInfo := mockJavaProcessWithErrors(t, root, nil, nil, expectedErr, expectedErr)
		fileInfo.SetUID(svc.UID{Name: "explicit-orders"})
		fileInfo.SetMetadata(map[attr.Name]string{serviceVersion: "2.0"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "explicit-orders", service.UID.Name)
		assert.Equal(t, "2.0", service.Metadata[serviceVersion])
	})

	t.Run("jar name is the final Java-specific fallback", func(t *testing.T) {
		root := t.TempDir()
		archivePath := filepath.Join(root, "app", "orders-1.2.3.jar")
		writeArchive(t, archivePath, nil)
		fileInfo := mockJavaProcess(t, root, []string{"-jar", "/app/orders-1.2.3.jar"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders-1.2.3", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("plain main class has no Java-specific fallback", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "classes"), 0o755))
		fileInfo := mockJavaProcess(t, root, []string{"-cp", "/app/classes", "com.example.Main"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("process lookup failure is returned", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockJavaProcessWithErrors(t, root, nil, map[string]string{
			envSpringApplicationName: "orders",
		}, expectedErr, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestSpringNamePrecedence(t *testing.T) {
	env := map[string]string{envSpringApplicationName: "environment"}
	args := []string{
		"-Dspring.application.name=old-system",
		"-Dspring.application.name=system",
		"-jar", "app.jar",
		"--spring.application.name=program",
	}

	assert.Equal(t, "program", springNameFromProgramArgs(args, env))
	assert.Equal(t, "system", springNameFromSystemProperties(args, env))
}

func TestSpringResourceParsing(t *testing.T) {
	t.Run("properties uses the last value and Java escapes", func(t *testing.T) {
		data := []byte(strings.Join([]string{
			"spring.application.name=old",
			"spring.application\\.name : order\\u0073-\\",
			"  service",
		}, "\n"))

		assert.Equal(t, "orders-service", propertyValue(data, springApplicationName))
	})

	t.Run("yaml reads the first document containing the nested name", func(t *testing.T) {
		data := []byte("other: value\n---\nspring:\n  application:\n    name: orders\n")

		assert.Equal(t, "orders", yamlSpringApplicationName(data))
	})

	t.Run("dotted yaml key is not treated as the nested Spring key", func(t *testing.T) {
		data := []byte("spring.application.name: orders\n")

		assert.Empty(t, yamlSpringApplicationName(data))
	})
}

func TestResolvePlaceholders(t *testing.T) {
	env := map[string]string{
		"APP_NAME":       "orders",
		"DEPLOYMENT_ENV": "prod",
		"MY_SERVICENAME": "checkout",
	}
	tests := []struct {
		name     string
		value    string
		expected string
		ok       bool
	}{
		{name: "exact environment name", value: "${APP_NAME}", expected: "orders", ok: true},
		{name: "Spring relaxed name", value: "${app.name}", expected: "orders", ok: true},
		{name: "Spring relaxed name removes dashes", value: "${my.service-name}", expected: "checkout", ok: true},
		{name: "embedded placeholders", value: "${APP_NAME}-${DEPLOYMENT_ENV}", expected: "orders-prod", ok: true},
		{name: "default", value: "${MISSING:fallback}", expected: "fallback", ok: true},
		{name: "missing", value: "${MISSING}", ok: false},
		{name: "empty", value: "", ok: false},
		{name: "malformed", value: "${APP_NAME", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, ok := resolvePlaceholders(tt.value, env)

			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestServiceResourceLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "application.properties")
	require.NoError(t, os.WriteFile(path, make([]byte, maxServiceResourceBytes+1), 0o644))

	data, ok := readRegularFile(path)

	assert.False(t, ok)
	assert.Nil(t, data)
}

func TestParseManifest(t *testing.T) {
	manifest := []byte("Implementation-Title: Orders \r\n Service\r\nImplementation-Version: 1.2.3\r\n\r\nName: ignored\r\n")

	assert.Equal(t, ServiceMetadata{Name: "Orders Service", Version: "1.2.3"}, parseManifest(manifest))
}

func mockJavaProcess(t *testing.T, root string, args []string, env map[string]string) *exec.FileInfo {
	t.Helper()
	return mockJavaProcessWithErrors(t, root, args, env, nil, nil)
}

func mockJavaProcessWithErrors(
	t *testing.T,
	root string,
	args []string,
	env map[string]string,
	cmdlineErr error,
	cwdErr error,
) *exec.FileInfo {
	t.Helper()

	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string { return root }
	cmdlineForPID = func(app.PID) (string, []string, error) {
		return "java", args, cmdlineErr
	}
	cwdForPID = func(app.PID) (string, error) { return "/app", cwdErr }
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCmdlineForPID
		cwdForPID = oldCwdForPID
	})

	return exec.New(exec.Init{
		Pid: app.PID(1234),
		Service: svc.Attrs{
			EnvVars:  env,
			Metadata: map[attr.Name]string{},
		},
	})
}

func writeArchive(t *testing.T, path string, files map[string]string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))

	file, err := os.Create(path)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	for name, contents := range files {
		entry, err := writer.Create(name)
		require.NoError(t, err)
		_, err = entry.Write([]byte(contents))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())
}
