// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

var expectedRoutes = []string{
	"/api",
	"/v1",
	"/jax",
	"/mn/submit",
	"/mn/things",
	"/v1/assets/*",
	"/api/assets/*",
	"/reactive/status",
	"/reactive/files/*",
	"/api/orders",
	"/v1/orders",
	"/api/orders/{orderId}",
	"/api/users/{id}",
	"/jax/items/{id}",
	"/mn/things/{name}",
	"/reactive/health/:probe",
	"/reactive/items/:itemId",
	"/v1/orders/{orderId}",
	"/v1/users/{id}",
}

func TestExtractRoutesFromSpringBootJar(t *testing.T) {
	fileInfo := javaFileInfo(t, []string{"-jar", "/spring-boot-app.jar"}, nil)

	routes, err := ExtractRoutes(fileInfo)

	require.NoError(t, err)
	assert.ElementsMatch(t, expectedRoutes, routes)
	assert.NotContains(t, routes, "/api/assets")
	assert.NotContains(t, routes, "/v1/assets")
	assert.NotContains(t, routes, "/api/${api.base}/dynamic")
	assert.NotContains(t, routes, "/reactive/files")
}

func TestExtractRoutesFromWarClasses(t *testing.T) {
	fileInfo := javaFileInfo(t, []string{"-jar", "/war-app.jar"}, nil)

	routes, err := ExtractRoutes(fileInfo)

	require.NoError(t, err)
	assert.ElementsMatch(t, expectedRoutes, routes)
}

func TestExtractRoutesFromExplicitClasspathDirectory(t *testing.T) {
	fileInfo := javaFileInfo(t, []string{"--class-path=/classes", "com.example.Main"}, map[string]string{
		envClasspath: "/does-not-exist",
	})

	routes, err := ExtractRoutes(fileInfo)

	require.NoError(t, err)
	assert.ElementsMatch(t, expectedRoutes, routes)
}

func TestExtractRoutesFromEnvClasspath(t *testing.T) {
	fileInfo := javaFileInfo(t, []string{"com.example.Main"}, map[string]string{
		envClasspath: "/classes",
	})

	routes, err := ExtractRoutes(fileInfo)

	require.NoError(t, err)
	assert.ElementsMatch(t, expectedRoutes, routes)
}

func TestExtractRoutesFromSingleClasspathJar(t *testing.T) {
	fileInfo := javaFileInfo(t, []string{"-cp", "/regular-app.jar", "com.example.Main"}, nil)

	routes, err := ExtractRoutes(fileInfo)

	require.NoError(t, err)
	assert.ElementsMatch(t, expectedRoutes, routes)
}

func TestExtractRoutesFromMultipleClasspathJars(t *testing.T) {
	fileInfo := javaFileInfo(t, []string{"-cp", "/regular-app.jar:/spring-boot-app.jar", "com.example.Main"}, nil)

	routes, err := ExtractRoutes(fileInfo)

	require.NoError(t, err)
	assert.ElementsMatch(t, expectedRoutes, routes)
}

func TestExtractRoutesFromWildcardClasspathJars(t *testing.T) {
	fileInfo := javaFileInfo(t, []string{"-cp", "/*", "com.example.Main"}, nil)

	routes, err := ExtractRoutes(fileInfo)

	require.NoError(t, err)
	assert.ElementsMatch(t, expectedRoutes, routes)
}

func TestSortRoutesPrefersStaticRoutesBeforeWildcardRoutes(t *testing.T) {
	routes := sortRoutes([]string{
		"/api/:version",
		"/api/v1",
		"/api/{id}",
		"/api/*",
		"/api/v1/users",
	})

	assert.Equal(t, []string{
		"/api/v1/users",
		"/api/v1",
		"/api/:version",
		"/api/{id}",
		"/api/*",
	}, routes)
}

func TestSortRoutesLetsPartialMatcherPreferStaticRoute(t *testing.T) {
	routes := sortRoutes([]string{"/api/:version", "/api/v1"})
	matcher := route.NewPartialRouteMatcher(routes)

	assert.Equal(t, "/api/v1", matcher.Find("/api/v1"))
}

func TestResolveProcessPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.jar")
	require.NoError(t, os.WriteFile(outside, []byte("not a jar"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape.jar")))

	path, ok := resolveProcessPath(root, "/", "/escape.jar")

	assert.False(t, ok)
	assert.Empty(t, path)
}

func javaFileInfo(t *testing.T, args []string, env map[string]string) *exec.FileInfo {
	t.Helper()

	pid := app.PID(1234)
	root := "test_files"
	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string {
		return root
	}
	cmdlineForPID = func(app.PID) (string, []string, error) {
		return "java", args, nil
	}
	cwdForPID = func(app.PID) (string, error) {
		return "/", nil
	}
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCmdlineForPID
		cwdForPID = oldCwdForPID
	})

	return exec.New(exec.Init{
		Pid: pid,
		Service: svc.Attrs{
			EnvVars: env,
		},
	})
}
