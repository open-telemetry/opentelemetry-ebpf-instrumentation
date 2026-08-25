// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	ObiJavaAgentFileName      = "obi-java-agent.jar"
	javaAgentEmbedPlaceholder = "OBI_JAVA_AGENT_PLACEHOLDER"
)

//go:embed embedded/obi-java-agent.jar
var embeddedJavaAgentBytes []byte

type JavaInjectError struct {
	Message string
}

func (e *JavaInjectError) Error() string {
	return e.Message
}

type JavaInjector struct {
	log             *slog.Logger
	cfg             *obi.Config
	currentAttachID int64
	mu              sync.Mutex
}

func NewJavaInjector(cfg *obi.Config) (*JavaInjector, error) {
	if !cfg.Java.Enabled {
		return nil, nil
	}
	if err := ensureEmbeddedAgent(); err != nil {
		return nil, err
	}

	return &JavaInjector{
		cfg:             cfg,
		log:             slog.With("component", "javaagent.Injector"),
		currentAttachID: 0,
	}, nil
}

func tempDirPath(root, dir string) (string, bool) {
	if root == "" {
		return "", false
	}

	cleanDir := filepath.Clean(dir)
	if !filepath.IsAbs(cleanDir) {
		return "", false
	}

	fullDir := filepath.Join(root, strings.TrimPrefix(cleanDir, "/"))
	rel, err := filepath.Rel(root, fullDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}

	return fullDir, true
}

func dirOK(root, dir string) bool {
	fullDir, ok := tempDirPath(root, dir)
	if !ok {
		return false
	}

	info, err := os.Stat(fullDir)
	return err == nil && info.IsDir()
}

func (i *JavaInjector) findTempDir(root, tempDirEnv string) (string, error) {
	if tempDirEnv != "" && dirOK(root, tempDirEnv) {
		return tempDirEnv, nil
	}

	tmpDir := "/tmp"
	if dirOK(root, tmpDir) {
		return tmpDir, nil
	}

	tmpDir = "/var/tmp"
	if dirOK(root, tmpDir) {
		return tmpDir, nil
	}

	return "", errors.New("couldn't find suitable temp directory for injection")
}

func (i *JavaInjector) nextAttachID() int64 {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.currentAttachID++
	return i.currentAttachID
}

func (i *JavaInjector) runIfCurrentAttach(
	attachID int64,
	fn func() error,
) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.currentAttachID != attachID {
		return nil
	}

	return fn()
}

// verifyTargetIdentity fails when Pid no longer refers to the process that was
// queued for injection. Every attach-side operation (entering the target's
// namespaces, dropping to its credentials, writing the agent into its root
// filesystem, and signaling it with SIGQUIT) is destructive to an unrelated
// process, so it must be preceded by this check.
//
// A target whose start time was never captured cannot be checked at all, so it
// is refused rather than injected on the assumption that its PID still holds
// the process discovery saw.
func verifyTargetIdentity(target InjectionTarget) error {
	if target.StartTime == 0 {
		return &JavaInjectError{Message: fmt.Sprintf("identity of process %d was not captured, refusing to inject", target.Pid)}
	}

	startTime, err := processStartTime(target.Pid)
	if err != nil {
		return &JavaInjectError{Message: fmt.Sprintf("cannot confirm identity of process %d: %s", target.Pid, err)}
	}

	if startTime != target.StartTime {
		return &JavaInjectError{Message: fmt.Sprintf("process %d was replaced before injection", target.Pid)}
	}

	return nil
}

// NewExecutable injects the Java agent into target. The attach deadline is
// derived from ctx, so canceling ctx abandons an in-flight attach instead of
// waiting out the configured timeout.
func (i *JavaInjector) NewExecutable(ctx context.Context, target InjectionTarget) error {
	if target.Type != svc.InstrumentableJava {
		return nil
	}

	// Nothing should signal a JVM once the caller has given up.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Injection is queued by PID and can start long after discovery, so the
	// process must be proven to be the one we discovered before we touch it.
	if err := verifyTargetIdentity(target); err != nil {
		return err
	}

	attachID := i.nextAttachID()

	ctx, cancel := context.WithTimeout(ctx, i.cfg.Java.Timeout)
	defer cancel()

	// Channel to receive the result
	type result struct {
		attached bool
		err      error
	}

	resultChan := make(chan result, 1)

	attacher := jvm.NewJAttacher(i.log, attachID, i.runIfCurrentAttach)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// We need to call cleanup here even though init may not have
	// happened, to ensure the case when the JVM never responds and
	// we've terminated with a timeout. Cleanup() is idempotent.
	defer func() {
		if err := attacher.Terminate(); err != nil {
			i.log.Warn("error on JVM attach cleanup", "error", err)
		}
	}()

	// Run the attach procedure in a goroutine, so that we can terminate on stuck attach
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultChan <- result{err: &JavaInjectError{Message: "attach failed"}}
			}
		}()

		ok, jdk8 := i.verifyJVMVersion(ctx, attacher, target.Pid)
		if !ok {
			resultChan <- result{err: &JavaInjectError{Message: "unsupported Java version for OpenTelemetry eBPF instrumentation"}}
			return
		}

		var loaded bool
		var err error
		if jdk8 {
			loaded, err = i.jdkAgentAlreadyLoadedHotspot8(ctx, attacher, target.Pid)
		} else {
			loaded, err = i.jdkAgentAlreadyLoaded(ctx, attacher, target.Pid)
		}

		if err != nil {
			resultChan <- result{err: err}
			return
		}

		if loaded {
			i.log.Info("OpenTelemetry eBPF Java Agent already loaded, not reloading")
			resultChan <- result{attached: false}
			return
		}

		i.log.Info("injecting OpenTelemetry eBPF instrumentation for Java process", "pid", target.Pid)

		// The handshake above can block for the whole attach timeout, which is
		// long enough for the PID to be recycled before we write into the
		// target's root filesystem and load the agent.
		if err := verifyTargetIdentity(target); err != nil {
			resultChan <- result{err: err}
			return
		}

		agentPath, err := i.copyAgent(target.Pid, target.TempDirEnv)
		if err != nil {
			i.log.Error("failed to extract java agent", "pid", target.Pid, "error", err)
			resultChan <- result{err: err}
			return
		}

		if err = i.attachJDKAgent(ctx, attacher, target.Pid, agentPath); err != nil {
			i.log.Error("couldn't attach OpenTelemetry eBPF Java Agent", "pid", target.Pid, "path", agentPath, "error", err)
			resultChan <- result{err: err}
			return
		}

		resultChan <- result{attached: true}
	}()

	// Wait for either completion or timeout
	select {
	case result := <-resultChan:
		return result.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			i.log.Warn("java attach timed out", "timeout", i.cfg.Java.Timeout, "pid", target.Pid)
			return &JavaInjectError{Message: "java attach timed out"}
		}
		i.log.Debug("java attach abandoned", "pid", target.Pid, "error", ctx.Err())
		return &JavaInjectError{Message: "java attach canceled"}
	}
}

func ensureEmbeddedAgent() error {
	if len(embeddedJavaAgentBytes) == 0 || strings.TrimSpace(string(embeddedJavaAgentBytes)) == javaAgentEmbedPlaceholder {
		return errors.New("embedded OBI java agent artifact is missing from this build; Java TLS telemetry generation will be disabled")
	}

	return nil
}

// to be changed in tests
var rootDirForPID func(app.PID) string = ebpfcommon.RootDirectoryForPID

func (i *JavaInjector) copyAgent(pid app.PID, tempDirEnv string) (string, error) {
	root := rootDirForPID(pid)
	tempDir, err := i.findTempDir(root, tempDirEnv)
	if err != nil {
		return "", fmt.Errorf("error accessing temp directory: %w", err)
	}

	fullTempDir, ok := tempDirPath(root, tempDir)
	if !ok {
		return "", fmt.Errorf("invalid temp directory for injection: %q", tempDir)
	}

	i.log.Info("found injection directory for process", "pid", pid, "path", fullTempDir)

	agentPathHost := filepath.Join(fullTempDir, ObiJavaAgentFileName)

	source := bytes.NewReader(embeddedJavaAgentBytes)
	target, err := os.CreateTemp(fullTempDir, ObiJavaAgentFileName+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("unable to create target OBI java agent: %w", err)
	}
	tmpTargetPath := target.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpTargetPath)
		}
	}()

	if _, err = target.ReadFrom(source); err != nil {
		return "", fmt.Errorf("error writing java agent to target location: %w", err)
	}

	if err = target.Chmod(0o644); err != nil {
		return "", fmt.Errorf("error setting permissions on target OBI java agent: %w", err)
	}

	if err = target.Close(); err != nil {
		return "", fmt.Errorf("error closing target OBI java agent: %w", err)
	}

	if err = os.Rename(tmpTargetPath, agentPathHost); err != nil {
		return "", fmt.Errorf("unable to move target OBI java agent into place: %w", err)
	}
	cleanup = false

	agentPathContainer := filepath.Join(tempDir, ObiJavaAgentFileName)

	return agentPathContainer, nil
}

func returnCodeLine(line string) (bool, error) {
	if strings.Contains(line, "return code: 0") || strings.Contains(line, "ATTACH_ACK") {
		return true, nil
	} else if strings.Contains(line, "return code:") {
		return true, fmt.Errorf("error executing command for the JVM %s", line)
	}

	return false, nil
}

func (i *JavaInjector) attachOpts() string {
	var opts []string
	if i.cfg.Java.Debug {
		opts = append(opts, "debug=true")
	}
	if i.cfg.Java.DebugInstrumentation {
		opts = append(opts, "debugBB=true")
	}

	if len(opts) == 0 {
		return ""
	}

	return "=" + strings.Join(opts, ",")
}

func (i *JavaInjector) attachJDKAgent(ctx context.Context, attacher *jvm.JAttacher, pid app.PID, path string) error {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	out, err := attacher.Attach(ctx, int(pid), []string{"load", "instrument", "false", path + i.attachOpts()}, false)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return err
	}

	defer out.Close()

	reader := bufio.NewReader(out)
	buf := bytes.Buffer{}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF { // hotspot terminates with EOF
				_, err := returnCodeLine(buf.String())
				if err != nil {
					return err
				}
				break
			}
			return fmt.Errorf("error reading line %w", err)
		}

		buf.WriteByte(b)
		if b == '\n' {
			if end, err := returnCodeLine(buf.String()); end {
				return err
			}

			buf.Reset()
		} else if b == 0 { // j9 terminates with 0
			if end, err := returnCodeLine(buf.String()); end {
				return err
			}
			break
		}
	}

	return nil
}

func (i *JavaInjector) jdkAgentAlreadyLoaded(ctx context.Context, attacher *jvm.JAttacher, pid app.PID) (bool, error) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.Attach(ctx, int(pid), []string{"jcmd", "VM.class_hierarchy"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent/0x<address>
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent/0x") {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		i.log.Error("error reading JVM command output", "pid", pid, "error", err)
		return false, err
	}

	return false, nil
}

// Hotspot version 8 doesn't support VM.class_hierarchy, we use GC.class_histogram and look for the class itself
// without the address
func (i *JavaInjector) jdkAgentAlreadyLoadedHotspot8(ctx context.Context, attacher *jvm.JAttacher, pid app.PID) (bool, error) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.Attach(ctx, int(pid), []string{"jcmd", "GC.class_histogram"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent") {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		i.log.Error("error reading JVM command output", "pid", pid, "error", err)
		return false, err
	}

	return false, nil
}

func (i *JavaInjector) verifyJVMVersion(ctx context.Context, attacher *jvm.JAttacher, pid app.PID) (bool, bool) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support VM.version command
	out, err := attacher.Attach(ctx, int(pid), []string{"jcmd", "VM.version"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, false
	}

	if out == nil {
		return true, false
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "JDK ") {
			// JDK 8 is special, failing to properly detect it can cause errors in applications if they are
			// loaded more than once
			return !strings.HasPrefix(line, "JDK 28"), strings.HasPrefix(line, "JDK 8")
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Error("error reading from scanner", "error", err)
	}

	return false, false
}
