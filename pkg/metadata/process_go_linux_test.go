// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"os"
	osexec "os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestResolveGoServiceMetadata(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/acme/checkout\n\ngo 1.21\n"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "lib"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", "lib.go"), []byte("package lib\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nimport _ \"github.com/acme/checkout/lib\"\nfunc main(){}\n"), 0o600))
	for _, tc := range []struct{ target, want string }{
		{".", "acme"}, {"main.go", ""},
	} {
		bin := filepath.Join(dir, "checkout")
		cmd := osexec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-ldflags=-s -w", "-o", bin, tc.target)
		cmd.Dir = dir
		cmd.Env = append(cmd.Environ(), "GOWORK=off", "GOFLAGS=")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		var stat syscall.Stat_t
		require.NoError(t, syscall.Stat(bin, &stat))
		fi := exec.New(exec.Init{ProExeLinkPath: bin, Dev: stat.Dev, Ino: stat.Ino, Service: svc.Attrs{UID: svc.UID{Name: "my-checkout"}}})
		disabled := NewProcessResourceDetectorWithConfig(&services.DiscoveryConfig{DisableGoServiceNamespaceInference: true})
		disabled.ResolveMetadata(svc.InstrumentableGolang, fi)
		require.Empty(t, fi.ServiceAttrs().UID.Namespace)
		detector := NewProcessResourceDetectorWithConfig(nil)
		detector.ResolveMetadata(svc.InstrumentableGolang, fi)
		got := fi.ServiceAttrs()
		require.Equal(t, tc.want, got.UID.Namespace)
		require.Equal(t, "my-checkout", got.UID.Name)
		fi.SetExplicitServiceNamespace("payments")
		detector.ResolveMetadata(svc.InstrumentableGolang, fi)
		got = fi.ServiceAttrs()
		require.Equal(t, "payments", got.UID.Namespace)
		require.False(t, got.AutoNamespace())
	}
}
