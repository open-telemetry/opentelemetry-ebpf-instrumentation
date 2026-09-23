// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func handleFor(t *testing.T, pid app.PID) *procs.ProcessHandle {
	t.Helper()

	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)

	handle, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { _ = handle.Close() })

	return handle
}

// startFatalSignalProcess runs a command that handles no signal, so SIGQUIT
// stays fatal to it and the refusal keeps waiting for a state that never comes.
//
// Which disposition the child starts from is not the command's to decide: exec
// resets a caught signal to its default but carries an ignored one through, so
// a test binary launched with SIGQUIT already ignored would hand that on and
// the process would read as safe to signal. Catching it here first makes the
// child start from the default whatever the environment did.
func startFatalSignalProcess(t *testing.T, name string, args ...string) (*procs.ProcessHandle, *exec.Cmd) {
	t.Helper()

	caught := make(chan os.Signal, 1)
	signal.Notify(caught, unix.SIGQUIT)
	t.Cleanup(func() { signal.Stop(caught) })

	cmd := exec.Command(name, args...)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	handle := handleFor(t, app.PID(cmd.Process.Pid))

	if handle.SignalDisposition(unix.SIGQUIT) != procs.SignalDispositionFatal {
		t.Skipf("this environment does not leave SIGQUIT fatal to a plain process: %s",
			procSignalState(t, handle.PID()))
	}

	return handle, cmd
}

// The Go runtime catches SIGQUIT, so the test binary is safe to signal.
func TestAttachRefusalHandled(t *testing.T) {
	require.Empty(t, attachRefusal(t.Context(), handleFor(t, app.PID(os.Getpid()))))
}

// A target the signal would terminate is refused, after waiting out the window
// in which a runtime may still install its handler.
func TestAttachRefusalSignalIsFatal(t *testing.T) {
	handle, _ := startFatalSignalProcess(t, "sleep", "600")

	require.Equal(t, procs.SignalDispositionFatal, handle.SignalDisposition(unix.SIGQUIT))

	start := time.Now()
	require.Equal(t, refusalSignalIsFatal, attachRefusal(t.Context(), handle))
	require.GreaterOrEqual(t, time.Since(start), attachWait,
		"a refusal that can still clear must wait out the window")
}

// Cancellation concludes nothing about the target, and must not wait out the
// window to say so. The target is one that would otherwise hold the wait open
// for its full duration, so the assertion cannot pass by accident.
func TestAttachRefusalCancelledDoesNotWait(t *testing.T) {
	handle, _ := startFatalSignalProcess(t, "sleep", "600")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	start := time.Now()
	reason := attachRefusal(ctx, handle)

	require.Equal(t, refusalDispositionUnknown, reason)
	require.Less(t, time.Since(start), attachWait)
}

// A target that is gone ends the wait rather than being polled to the deadline.
func TestAttachRefusalStopsOnExit(t *testing.T) {
	handle, cmd := startFatalSignalProcess(t, "sleep", "600")

	require.NoError(t, cmd.Process.Kill())
	_, err := cmd.Process.Wait()
	require.NoError(t, err)

	start := time.Now()
	require.Equal(t, refusalDispositionUnknown, attachRefusal(t.Context(), handle))
	require.Less(t, time.Since(start), attachWait)
}

func commandLine(args ...string) []byte {
	return []byte(strings.Join(args, "\x00") + "\x00")
}

// Only the arguments HotSpot parses as VM options count. Everything from the
// program onwards belongs to the application, so a launcher handing the flag to
// a child JVM is not setting it for the JVM that holds it.
func TestVMOptionsStopAtTheProgram(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmdline  []byte
		disabled bool
		found    bool
	}{
		{"absent", commandLine("java", "-Xmx1g", "-cp", ".", "App"), false, false},
		{"disabled", commandLine("java", attachDisablingOption, "App"), true, true},
		{"enabled", commandLine("java", attachEnablingOption, "App"), false, true},
		{
			"last wins, off",
			commandLine("java", attachEnablingOption, attachDisablingOption, "App"),
			true, true,
		},
		{
			"last wins, on",
			commandLine("java", attachDisablingOption, attachEnablingOption, "App"),
			false, true,
		},
		{"no sign is not a setting", commandLine("java", "DisableAttachMechanism"), false, false},
		{
			"an argument that merely contains the flag",
			commandLine("java", "Launcher", "--child-jvm-opts="+attachDisablingOption),
			false, false,
		},
		{
			"a bare application argument after the main class",
			commandLine("java", "-cp", ".", "Launcher", attachDisablingOption),
			false, false,
		},
		{
			"a bare application argument after -jar",
			commandLine("java", "-jar", "app.jar", attachDisablingOption),
			false, false,
		},
		{
			"the class path value is not the main class",
			commandLine("java", "-cp", "lib.jar", attachDisablingOption, "App"),
			true, true,
		},
		{
			"an application argument after a module",
			commandLine("java", "-m", "mod/Main", attachDisablingOption),
			false, false,
		},
		// --add-opens and its siblings take their value as the next argument,
		// which must not be mistaken for the main class.
		{
			"a module option value is not the main class",
			commandLine("java", "--add-opens", "java.base/java.lang=ALL-UNNAMED",
				attachDisablingOption, "-jar", "app.jar"),
			true, true,
		},
		{
			"an export option value is not the main class",
			commandLine("java", "--add-exports", "java.base/sun.nio.ch=ALL-UNNAMED",
				attachDisablingOption, "App"),
			true, true,
		},
		{
			"a patched module value is not the main class",
			commandLine("java", "--patch-module", "java.base=patch.jar", attachDisablingOption, "App"),
			true, true,
		},
		// The equals form carries its own value, so the next argument is not one.
		{
			"an option written with an equals value",
			commandLine("java", "--add-opens=java.base/java.lang=ALL-UNNAMED",
				attachDisablingOption, "App"),
			true, true,
		},
		{
			"a module named with an equals value still ends the options",
			commandLine("java", "--module=mod/Main", attachDisablingOption),
			false, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disabled, found := lastAttachSetting(vmOptions(tc.cmdline))
			require.Equal(t, tc.found, found)
			require.Equal(t, tc.disabled, disabled)
		})
	}
}

// Lines as they appear in /proc/<pid>/maps: OpenJ9 maps its own VM library next
// to the libjvm.so redirector, HotSpot maps only libjvm.so.
func TestMapsOpenJ9(t *testing.T) {
	const (
		openJ9Maps = "7f1c2a400000-7f1c2a5f0000 r-xp 00000000 08:01 1234 " +
			"/opt/java/openjdk/lib/default/libj9vm29.so\n" +
			"7f1c2b000000-7f1c2b010000 r-xp 00000000 08:01 1235 /opt/java/openjdk/lib/server/libjvm.so\n"
		hotSpotMaps = "7f1c2b000000-7f1c2b900000 r-xp 00000000 08:01 1235 " +
			"/opt/java/openjdk/lib/server/libjvm.so\n"
	)

	require.True(t, mapsOpenJ9([]byte(openJ9Maps)))
	require.False(t, mapsOpenJ9([]byte(hotSpotMaps)))
	require.False(t, mapsOpenJ9(nil))
}

func TestEnvironValue(t *testing.T) {
	environ := []byte("PATH=/bin\x00JAVA_TOOL_OPTIONS=-Xmx1g\t" + attachDisablingOption + "\x00HOME=/root\x00")

	// The value is split on any whitespace, the way the launcher does, so one
	// variable holding several options is matched option by option.
	disabled, found := lastAttachSetting(optionWords(environValue(environ, "JAVA_TOOL_OPTIONS")))
	require.True(t, found)
	require.True(t, disabled)

	require.Equal(t, []byte("/bin"), environValue(environ, "PATH"))
	require.Nil(t, environValue(environ, "MAVEN_OPTS"))

	// A variable the launcher does not fold into the options must not be read as
	// one that it does.
	other := []byte("MAVEN_OPTS=" + attachDisablingOption + "\x00")
	require.Nil(t, environValue(other, "JAVA_TOOL_OPTIONS"))
}

const sleeperSource = `public class Sleeper {
    public static void main(String[] a) throws Exception { Thread.sleep(600000); }
}`

// javaIsOpenJ9 reports whether the JDK on PATH is OpenJ9, skipping when there is
// no JDK at all.
func javaIsOpenJ9(t *testing.T) bool {
	t.Helper()

	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("no JDK on PATH")
	}

	out, err := exec.Command("java", "-version").CombinedOutput()
	require.NoError(t, err, "java -version: %s", out)

	return strings.Contains(string(out), "OpenJ9")
}

// startJVM runs a HotSpot JVM. The attach refusal is exercised directly here,
// and an OpenJ9 VM reaching it is refused on that ground alone, so these tests
// need HotSpot.
func startJVM(t *testing.T, env []string, args ...string) *procs.ProcessHandle {
	t.Helper()

	if javaIsOpenJ9(t) {
		t.Skip("the JDK on PATH is OpenJ9; these tests cover HotSpot")
	}

	return launchJVM(t, env, args...)
}

func launchJVM(t *testing.T, env []string, args ...string) *procs.ProcessHandle {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "Sleeper.java")
	require.NoError(t, os.WriteFile(src, []byte(sleeperSource), 0o600))

	out, err := exec.Command("javac", "-d", dir, src).CombinedOutput()
	require.NoError(t, err, "javac: %s", out)

	cmd := exec.Command("java", append(append([]string{}, args...), "-cp", dir, "Sleeper")...)
	cmd.Env = append(os.Environ(), env...)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	pid := app.PID(cmd.Process.Pid)

	var handle *procs.ProcessHandle
	require.Eventually(t, func() bool {
		startTime, err := procs.StartTime(pid)
		if err != nil {
			return false
		}
		handle, err = procs.OpenProcessHandle(pid, startTime)
		return err == nil
	}, 30*time.Second, 100*time.Millisecond, "JVM never became readable")

	t.Cleanup(func() { _ = handle.Close() })

	return handle
}

// Covers the startup window too: the wait has to outlast HotSpot installing its
// handler, or an ordinary JVM is refused for a condition that clears.
func TestAttachRefusalLiveJVM(t *testing.T) {
	handle := startJVM(t, nil)

	require.False(t, isOpenJ9(handle))
	require.Empty(t, attachRefusal(t.Context(), handle))
}

// OpenJ9 with attach disabled creates no attach directory, so it is not
// recognized as OpenJ9 and lands here. It catches SIGQUIT, so the signal cannot
// kill it, but OpenJ9 never attaches in response to one: all it would get is a
// javacore written next to the application.
func TestAttachRefusalOpenJ9AttachDisabled(t *testing.T) {
	if !javaIsOpenJ9(t) {
		t.Skip("the JDK on PATH is not OpenJ9")
	}

	handle := launchJVM(t, nil, "-Dcom.ibm.tools.attach.enable=no")

	require.Eventually(t, func() bool { return isOpenJ9(handle) },
		10*time.Second, 50*time.Millisecond, "OpenJ9 never mapped its VM library")
	require.Equal(t, refusalOpenJ9, attachRefusal(t.Context(), handle))
}

// A JVM that will not answer the handshake still catches SIGQUIT, so the signal
// is harmless but useless: it buys a thread dump in the application's own
// output and nothing else.
func TestAttachRefusalDisableAttachMechanism(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		args []string
	}{
		{"on the command line", nil, []string{attachDisablingOption}},
		{"via JAVA_TOOL_OPTIONS", []string{"JAVA_TOOL_OPTIONS=" + attachDisablingOption}, nil},
		{"via _JAVA_OPTIONS", []string{"_JAVA_OPTIONS=" + attachDisablingOption}, nil},
		// Only the JDK 9+ launcher reads JDK_JAVA_OPTIONS.
		{
			"via JDK_JAVA_OPTIONS",
			[]string{"JDK_JAVA_OPTIONS=" + attachDisablingOption},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle := startJVM(t, tc.env, tc.args...)

			require.True(t, attachDisabled(handle))
			require.Equal(t, refusalAttachDisabled, attachRefusal(t.Context(), handle))
		})
	}
}

func TestAttachDisabledHonoursOptionPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		args []string
	}{
		{"enabling spelling alone", nil, []string{attachEnablingOption}},
		{
			"command line overrides JAVA_TOOL_OPTIONS",
			[]string{"JAVA_TOOL_OPTIONS=" + attachDisablingOption},
			[]string{attachEnablingOption},
		},
		{
			"command line overrides JDK_JAVA_OPTIONS",
			[]string{"JDK_JAVA_OPTIONS=" + attachDisablingOption},
			[]string{attachEnablingOption},
		},
		{
			"a variable the launcher ignores is not an option source",
			[]string{"MAVEN_OPTS=" + attachDisablingOption},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle := startJVM(t, tc.env, tc.args...)

			require.False(t, attachDisabled(handle))
			require.Empty(t, attachRefusal(t.Context(), handle))
		})
	}
}

// _JAVA_OPTIONS is applied after the command line, so it overrides it.
func TestAttachDisabledJavaOptionsOverridesCommandLine(t *testing.T) {
	handle := startJVM(t,
		[]string{"_JAVA_OPTIONS=" + attachDisablingOption},
		attachEnablingOption)

	require.True(t, attachDisabled(handle))
	require.Equal(t, refusalAttachDisabled, attachRefusal(t.Context(), handle))
}

// Whether -Xrs leaves SIGQUIT fatal also depends on the disposition the JVM
// inherited, which the launching environment controls, so the condition is
// checked rather than assumed. The fatal path itself is covered without a JVM
// by TestAttachRefusalSignalIsFatal.
func TestAttachRefusalXrs(t *testing.T) {
	handle := startJVM(t, nil, "-Xrs")

	if handle.SignalDisposition(unix.SIGQUIT) != procs.SignalDispositionFatal {
		t.Skipf("-Xrs did not leave SIGQUIT fatal here: %s", procSignalState(t, handle.PID()))
	}

	require.Equal(t, refusalSignalIsFatal, attachRefusal(t.Context(), handle))
}

func procSignalState(t *testing.T, pid app.PID) string {
	t.Helper()

	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return fmt.Sprintf("status unreadable: %v", err)
	}

	var fields []string
	for line := range strings.SplitSeq(string(status), "\n") {
		if strings.HasPrefix(line, "SigIgn:") || strings.HasPrefix(line, "SigCgt:") {
			fields = append(fields, strings.TrimSpace(line))
		}
	}

	return strings.Join(fields, " ")
}
