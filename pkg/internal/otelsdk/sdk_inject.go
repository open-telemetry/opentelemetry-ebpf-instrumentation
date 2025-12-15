// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package otelsdk

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/grafana/jvmtools/jvm"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

type SDKInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

func NewSDKInjector(cfg *obi.Config) *SDKInjector {
	return &SDKInjector{
		cfg: cfg,
		log: slog.With("component", "otelsdk.Injector"),
	}
}

func dirOK(root, dir string) bool {
	fullDir := filepath.Join(root, dir)

	info, err := os.Stat(fullDir)
	return err == nil && info.IsDir()
}

func (i *SDKInjector) findTempDir(root string, ie *ebpf.Instrumentable) (string, error) {
	if tmpDir, ok := ie.FileInfo.Service.EnvVars["TMPDIR"]; ok {
		if dirOK(root, tmpDir) {
			return tmpDir, nil
		}
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

func (i *SDKInjector) NewExecutable(ie *ebpf.Instrumentable) error {
	if ie.Type == svc.InstrumentableJava {
		ok := i.verifyJVMVersion(ie.FileInfo.Pid)
		if !ok {
			i.log.Info("unsupported Java version for OpenTelemetry eBPF instrumentation")
			return errors.New("unsupported Java VM version")
		}

		loaded, err := i.jdkAgentAlreadyLoaded(ie.FileInfo.Pid)
		if err != nil {
			return err
		}

		if loaded {
			i.log.Info("OpenTelemetry eBPF Java Agent already loaded, not instrumenting.")
			return errors.New("OpenTelemetry eBPF Java Agent already loaded")
		}

		i.log.Info("injecting OpenTelemetry eBPF instrumentation for Java process", "pid", ie.FileInfo.Pid)

		agentPath, err := i.extractAgent(ie)
		if err != nil {
			i.log.Error("failed to extract java agent", "pid", ie.FileInfo.Pid, "error", err)
			return err
		}

		if err = i.attachJDKAgent(ie.FileInfo.Pid, agentPath); err != nil {
			i.log.Error("couldn't attach OpenTelemetry eBPF Java Agent", "pid", ie.FileInfo.Pid, "path", agentPath, "error", err)
			return err
		}

		return nil
	}

	return errors.New("OpenTelemetry eBPF Java instrumentation not possible")
}

func (i *SDKInjector) extractAgent(ie *ebpf.Instrumentable) (string, error) {
	root := ebpfcommon.RootDirectoryForPID(ie.FileInfo.Pid)
	tempDir, err := i.findTempDir(root, ie)
	if err != nil {
		return "", fmt.Errorf("error accessing temp directory: %w", err)
	}

	fullTempDir := filepath.Join(root, tempDir)

	i.log.Info("found injection directory for process", "pid", ie.FileInfo.Pid, "path", fullTempDir)

	const agentFile = "obi-java-agent.jar"

	agentPathHost := filepath.Join(fullTempDir, agentFile)

	if err = os.WriteFile(agentPathHost, _agentBytes, 0o644); err != nil {
		return "", fmt.Errorf("error writing file: %w", err)
	}

	agentPathContainer := filepath.Join(tempDir, agentFile)

	return agentPathContainer, nil
}

func (i *SDKInjector) attachJDKAgent(pid int32, path string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	attacher := jvm.NewJAttacher(i.log)
	attacher.Init()
	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()

	out, err := attacher.Attach(int(pid), []string{"load", "instrument", "false", path}, false)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return err
	}

	scanner := bufio.NewScanner(out)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "return code: 0") {
			return nil
		} else if strings.Contains(line, "return code:") {
			i.log.Error("error executing command for the JVM", "pid", pid, "message", line)
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Warn("error reading JVM output", "error", err)
	}

	return nil
}

func (i *SDKInjector) jdkAgentAlreadyLoaded(pid int32) (bool, error) {
	attacher := jvm.NewJAttacher(i.log)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	attacher.Init()
	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()

	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.Attach(int(pid), []string{"jcmd", "VM.class_hierarchy"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		// We check for io.opentelemetry.obi.java.Agent/0x<address>
		if strings.Contains(scanner.Text(), "io.opentelemetry.obi.java.Agent/0x") {
			return true, nil
		}
	}

	return false, nil
}

func (i *SDKInjector) verifyJVMVersion(pid int32) bool {
	attacher := jvm.NewJAttacher(i.log)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	attacher.Init()
	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()

	// OpenJ9 doesn't support VM.version command
	out, err := attacher.Attach(int(pid), []string{"jcmd", "VM.version"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false
	}

	if out == nil {
		return true
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "JDK ") {
			return !strings.HasPrefix(line, "JDK 26")
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Error("error reading from scanner", "error", err)
	}

	return false
}

var _agentBytes []byte
