// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestRunIfCurrentAttachHoldsLockWhileRunningAction(t *testing.T) {
	injector := &JavaInjector{}
	attachID := injector.nextAttachID()

	actionStarted := make(chan struct{})
	finishAction := make(chan struct{})
	actionDone := make(chan error, 1)
	go func() {
		actionDone <- injector.runIfCurrentAttach(attachID, func() error {
			close(actionStarted)
			<-finishAction
			return nil
		})
	}()

	<-actionStarted
	lockWasAvailable := injector.mu.TryLock()
	if lockWasAvailable {
		injector.mu.Unlock()
	}

	nextAttachID := make(chan int64, 1)
	go func() {
		nextAttachID <- injector.nextAttachID()
	}()

	close(finishAction)
	require.NoError(t, <-actionDone)
	require.Equal(t, int64(2), <-nextAttachID)
	require.False(t, lockWasAvailable)

	actionRan := false
	require.NoError(t, injector.runIfCurrentAttach(attachID, func() error {
		actionRan = true
		return nil
	}))
	require.False(t, actionRan)
}

func TestJavaInjector_CopyAgent(t *testing.T) {
	oldJavaAgentBytes := embeddedJavaAgentBytes
	embeddedJavaAgentBytes = []byte("test agent content")
	t.Cleanup(func() {
		embeddedJavaAgentBytes = oldJavaAgentBytes
	})

	tests := []struct {
		name          string
		setupTempDir  func(t *testing.T, pid app.PID) string
		envVars       map[string]string
		pid           app.PID
		expectError   bool
		errorContains string
		verifyFile    bool
	}{
		{
			name: "successful copy to /tmp",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "successful copy to TMPDIR from env",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				customTmpDir := filepath.Join(procRoot, "custom", "tmp")
				require.NoError(t, os.MkdirAll(customTmpDir, 0o755))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "TMPDIR absolute path outside process root is ignored",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "/proc/1/root/etc",
			},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "TMPDIR relative path escape is ignored",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "../../../etc",
			},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "fallback to /var/tmp when /tmp not available",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "var", "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "error when no temp directory available",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(procRoot, 0o755))
				return tmpDir
			},
			envVars:       map[string]string{},
			pid:           1000,
			expectError:   true,
			errorContains: "error accessing temp directory",
			verifyFile:    false,
		},
		{
			name: "error when target directory not writable",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				tmpPath := filepath.Join(procRoot, "tmp")
				require.NoError(t, os.MkdirAll(tmpPath, 0o755))
				require.NoError(t, os.Chmod(tmpPath, 0o555))
				return tmpDir
			},
			envVars:       map[string]string{},
			pid:           1000,
			expectError:   true,
			errorContains: "unable to create target OBI java agent",
			verifyFile:    false,
		},
		{
			name: "agent content correctly copied",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "copy does not follow existing symlink target",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				targetDir := filepath.Join(procRoot, "tmp")
				require.NoError(t, os.MkdirAll(targetDir, 0o755))

				victim := filepath.Join(tmpDir, "victim")
				require.NoError(t, os.WriteFile(victim, []byte("do not overwrite"), 0o644))
				require.NoError(t, os.Symlink(victim, filepath.Join(targetDir, ObiJavaAgentFileName)))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := tt.setupTempDir(t, tt.pid)

			injector := &JavaInjector{
				cfg: &obi.DefaultConfig,
				log: slog.With("component", "javaagent.Injector"),
			}

			root := filepath.Join(tmpDir, "proc", "root")
			resultPath, err := injector.copyAgent(root, tt.pid, tt.envVars["TMPDIR"])

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, resultPath)

				if tt.verifyFile {
					// Verify the file was created in the host filesystem
					procRoot := filepath.Join(tmpDir, "proc", "root")
					expectedHostPath := filepath.Join(procRoot, strings.TrimPrefix(resultPath, "/"))

					info, err := os.Stat(expectedHostPath)
					require.NoError(t, err)
					assert.False(t, info.IsDir())
					assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

					// Verify content matches
					originalContent := embeddedJavaAgentBytes
					copiedContent, err := os.ReadFile(expectedHostPath)
					require.NoError(t, err)
					assert.Equal(t, originalContent, copiedContent)

					victimPath := filepath.Join(tmpDir, "victim")
					if _, err := os.Stat(victimPath); err == nil {
						victimContent, readErr := os.ReadFile(victimPath)
						require.NoError(t, readErr)
						assert.Equal(t, []byte("do not overwrite"), victimContent)
					}
				}
			}
		})
	}
}

func TestJavaInjector_FindTempDir(t *testing.T) {
	tests := []struct {
		name        string
		setupDirs   func(t *testing.T, root string)
		envVars     map[string]string
		expectError bool
		expectedDir string
	}{
		{
			name: "prefer TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "custom", "tmp"), 0o755))
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			},
			expectError: false,
			expectedDir: "/custom/tmp",
		},
		{
			name: "fallback to /tmp",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars:     map[string]string{},
			expectError: false,
			expectedDir: "/tmp",
		},
		{
			name: "fallback to /var/tmp when /tmp missing",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "var", "tmp"), 0o755))
			},
			envVars:     map[string]string{},
			expectError: false,
			expectedDir: "/var/tmp",
		},
		{
			name: "error when no temp dir available",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(root, 0o755))
			},
			envVars:     map[string]string{},
			expectError: true,
		},
		{
			name: "ignore invalid TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/nonexistent",
			},
			expectError: false,
			expectedDir: "/tmp",
		},
		{
			name: "ignore escaping TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/proc/1/root/etc",
			},
			expectError: false,
			expectedDir: "/tmp",
		},
		{
			name: "ignore relative TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "../../../etc",
			},
			expectError: false,
			expectedDir: "/tmp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setupDirs(t, root)

			injector := &JavaInjector{
				cfg: &obi.Config{},
			}

			tmpDir, err := injector.findTempDir(root, tt.envVars["TMPDIR"])

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "couldn't find suitable temp directory")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedDir, tmpDir)
			}
		})
	}
}

func TestDirOK(t *testing.T) {
	tests := []struct {
		name      string
		setupDirs func(t *testing.T) (root string, dir string)
		expected  bool
	}{
		{
			name: "valid directory exists",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/testdir"
				require.NoError(t, os.MkdirAll(filepath.Join(root, strings.TrimPrefix(dir, "/")), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "directory does not exist",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, "/nonexistent"
			},
			expected: false,
		},
		{
			name: "path is a file not a directory",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				file := "/testfile"
				require.NoError(t, os.WriteFile(filepath.Join(root, strings.TrimPrefix(file, "/")), []byte("content"), 0o644))
				return root, file
			},
			expected: false,
		},
		{
			name: "nested directory exists",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/nested/path/dir"
				require.NoError(t, os.MkdirAll(filepath.Join(root, strings.TrimPrefix(dir, "/")), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "empty root path",
			setupDirs: func(_ *testing.T) (string, string) {
				return "", "/tmp"
			},
			expected: false,
		},
		{
			name: "empty dir path",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, ""
			},
			expected: false,
		},
		{
			name: "absolute path directory",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/abs/path"
				require.NoError(t, os.MkdirAll(filepath.Join(root, strings.TrimPrefix(dir, "/")), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "relative traversal escapes root",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, "../../../etc"
			},
			expected: false,
		},
		{
			name: "directory with no permissions",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/noperm"
				dirPath := filepath.Join(root, strings.TrimPrefix(dir, "/"))
				require.NoError(t, os.MkdirAll(dirPath, 0o755))
				require.NoError(t, os.Chmod(dirPath, 0o000))
				t.Cleanup(func() {
					err := os.Chmod(dirPath, 0o755)
					assert.NoError(t, err)
				})
				return root, dir
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, dir := tt.setupDirs(t)
			result := dirOK(root, dir)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaInjector_AttachOpts(t *testing.T) {
	tests := []struct {
		name           string
		debug          bool
		debugBB        bool
		runtimeMetrics bool
		expected       string
	}{
		{
			name:     "no options enabled",
			debug:    false,
			debugBB:  false,
			expected: "",
		},
		{
			name:           "runtime metrics only",
			runtimeMetrics: true,
			expected:       "=runtimeMetrics=true,runtimeMetricsIntervalNanos=2000000000",
		},
		{
			name:     "debug only",
			debug:    true,
			debugBB:  false,
			expected: "=debug=true",
		},
		{
			name:     "debugBB only",
			debug:    false,
			debugBB:  true,
			expected: "=debugBB=true",
		},
		{
			name:           "all options enabled",
			debug:          true,
			debugBB:        true,
			runtimeMetrics: true,
			expected:       "=debug=true,debugBB=true,runtimeMetrics=true,runtimeMetricsIntervalNanos=2000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &obi.Config{
				Java: obi.JavaConfig{
					Debug:                tt.debug,
					DebugInstrumentation: tt.debugBB,
				},
				JVMRuntimeMetrics: obi.JVMRuntimeMetricsConfig{
					SamplingInterval: 2 * time.Second,
				},
			}

			injector := &JavaInjector{
				cfg: cfg,
				log: slog.With("component", "javaagent.Injector"),
			}
			features := export.FeatureApplicationRED
			if tt.runtimeMetrics {
				features |= export.FeatureApplicationRuntime
			}
			ie := &ebpf.Instrumentable{
				FileInfo: exec.New(exec.Init{
					Service: svc.Attrs{Features: features},
				}),
			}

			runtimeMetricsEnabled := ie.FileInfo.ServiceAttrs().Features.AppRuntime()
			result := injector.attachOpts(runtimeMetricsEnabled)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// The attach deadline must be derived from the caller's context, so a shutdown
// abandons the attach instead of signaling a JVM and waiting out the timeout.
func TestJavaInjector_NewExecutable_CanceledContextStartsNoAttach(t *testing.T) {
	injector := &JavaInjector{
		log: slog.Default(),
		cfg: &obi.Config{Java: obi.JavaConfig{Enabled: true, Timeout: time.Hour}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := injector.NewExecutable(ctx, InjectionTarget{
		Type: svc.InstrumentableJava,
		Pid:  app.PID(os.Getpid()),
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, int64(0), injector.currentAttachID, "no attach should have been started")
}

type blockingAttachResponse struct {
	readStarted sync.Once
	closeOnce   sync.Once
	started     chan struct{}
	closed      chan struct{}
	release     chan struct{}
	readDone    chan struct{}
}

func newBlockingAttachResponse() *blockingAttachResponse {
	return &blockingAttachResponse{
		started:  make(chan struct{}),
		closed:   make(chan struct{}),
		release:  make(chan struct{}),
		readDone: make(chan struct{}),
	}
}

func (r *blockingAttachResponse) Read([]byte) (int, error) {
	r.readStarted.Do(func() { close(r.started) })
	<-r.closed
	<-r.release
	close(r.readDone)
	return 0, io.ErrClosedPipe
}

func (r *blockingAttachResponse) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

type blockingResponseAttacher struct {
	response *blockingAttachResponse
}

func (*blockingResponseAttacher) Init()                         {}
func (*blockingResponseAttacher) Cleanup(context.Context) error { return nil }
func (*blockingResponseAttacher) Terminate() error              { return nil }
func (a *blockingResponseAttacher) Attach(
	ctx context.Context,
	_ *procs.ProcessHandle,
	_ []string,
	_ bool,
) (io.ReadCloser, error) {
	context.AfterFunc(ctx, func() { _ = a.response.Close() })
	return a.response, nil
}

// The queue is only serialized if cancellation joins the response reader. A
// returned outer call with this read still alive could overlap the next JVM's
// credentials and outlive pipeline shutdown.
func TestJavaInjector_NewExecutableCancellationJoinsResponseRead(t *testing.T) {
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, process.Close()) })

	response := newBlockingAttachResponse()
	injector := &JavaInjector{
		log: slog.Default(),
		cfg: &obi.Config{Java: obi.JavaConfig{Enabled: true, Timeout: time.Hour}},
		newAttacher: func(*slog.Logger, int64, func(int64, func() error) error) jvmAttacher {
			return &blockingResponseAttacher{response: response}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- injector.NewExecutable(ctx, InjectionTarget{
			Type:      svc.InstrumentableJava,
			Pid:       pid,
			StartTime: startTime,
			Process:   process,
		})
	}()

	<-response.started
	cancel()
	<-response.closed

	select {
	case err := <-done:
		t.Fatalf("NewExecutable returned before its response reader stopped: %v", err)
	default:
	}

	close(response.release)
	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "canceled")
	case <-time.After(time.Second):
		t.Fatal("NewExecutable did not join the canceled response reader")
	}
	select {
	case <-response.readDone:
	default:
		t.Fatal("response read was still alive after NewExecutable returned")
	}
}

func TestJavaInjector_NewExecutable_IgnoresNonJavaTarget(t *testing.T) {
	injector := &JavaInjector{
		log: slog.Default(),
		cfg: &obi.Config{Java: obi.JavaConfig{Enabled: true, Timeout: time.Hour}},
	}

	require.NoError(t, injector.NewExecutable(context.Background(), InjectionTarget{
		Type: svc.InstrumentableGolang,
		Pid:  app.PID(os.Getpid()),
	}))
	assert.Equal(t, int64(0), injector.currentAttachID)
}

func TestNewJavaInjector_Disabled(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	cfg := obi.DefaultConfig
	cfg.Java.Enabled = false
	cfg.Metrics.Features = export.FeatureApplicationRuntime
	injector, err := NewJavaInjector(&cfg)

	require.NoError(t, err)
	assert.Nil(t, injector)
	assert.Contains(t, logs.String(), "JVM class loading, thread, and CPU metrics will not be collected")
}

func TestNewJavaInjector_MissingEmbeddedAgent(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = nil

	injector, err := NewJavaInjector(&obi.Config{
		Java: obi.JavaConfig{
			Enabled: true,
		},
	})

	require.Error(t, err)
	assert.Nil(t, injector)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}

func TestNewJavaInjector_PlaceholderEmbeddedAgent(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = []byte(javaAgentEmbedPlaceholder + "\n")

	injector, err := NewJavaInjector(&obi.Config{
		Java: obi.JavaConfig{
			Enabled: true,
		},
	})

	require.Error(t, err)
	assert.Nil(t, injector)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}

func TestEnsureEmbeddedAgent_ForgotToEmbed(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = nil
	err := ensureEmbeddedAgent()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}

func TestEnsureEmbeddedAgent_PlaceholderBytesError(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = []byte(javaAgentEmbedPlaceholder + "\n")
	err := ensureEmbeddedAgent()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}
