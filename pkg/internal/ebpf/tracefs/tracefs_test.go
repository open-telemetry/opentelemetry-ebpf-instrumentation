// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tracefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestUnescapeMountPath(t *testing.T) {
	tests := map[string]struct {
		path string
		want string
	}{
		"unchanged":              {path: "/sys/kernel/tracing", want: "/sys/kernel/tracing"},
		"mountinfo escapes":      {path: `/trace\040space\011tab\012line\134slash`, want: "/trace space\ttab\nline\\slash"},
		"unknown escape":         {path: `/trace\043hash`, want: `/trace\043hash`},
		"escaped backslash only": {path: `/trace\134040space`, want: `/trace\040space`},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, unescapeMountPath(test.path))
		})
	}
}

func TestRandomTraceFSGroup(t *testing.T) {
	group, err := randomTraceFSGroup()

	require.NoError(t, err)
	assert.Regexp(t, `^obi_[0-9a-f]{16}$`, group)
}

func TestWritableTraceFSMountSkipsReadOnlyMount(t *testing.T) {
	mounts := []*procfs.MountInfo{
		{FSType: "tracefs", Root: "/", MountPoint: "/sys/kernel/tracing", Options: map[string]string{"ro": ""}},
		{FSType: "tracefs", Root: "/", MountPoint: "/sys/kernel/debug/tracing", Options: map[string]string{"rw": ""}},
	}

	assert.Equal(t, "/sys/kernel/debug/tracing", writableTraceFSMount(mounts))
}

func TestTraceFSEventCloseRemovesEventOnce(t *testing.T) {
	eventsFile := filepath.Join(t.TempDir(), "uprobe_events")
	require.NoError(t, os.WriteFile(eventsFile, nil, 0o600))
	event := &traceFSEvent{eventsFile: eventsFile, group: "obi_abcd", name: "probe"}

	require.NoError(t, event.Close())
	require.NoError(t, event.Close())

	commands, err := os.ReadFile(eventsFile)
	require.NoError(t, err)
	assert.Equal(t, "-:obi_abcd/probe", string(commands))
}

func TestTraceFSLinksRemoveGroupOnce(t *testing.T) {
	eventsFile := filepath.Join(t.TempDir(), "uprobe_events")
	require.NoError(t, os.WriteFile(eventsFile, nil, 0o600))

	links := []*traceFSLink{
		newTestTraceFSLink(t, &traceFSEvent{eventsFile: eventsFile, group: "obi_abcd", name: "probe_0"}),
		newTestTraceFSLink(t, &traceFSEvent{eventsFile: eventsFile, group: "obi_abcd", name: "probe_1"}),
	}
	group := &traceFSEventGroup{eventsFile: eventsFile, name: "obi_abcd"}
	batch := &traceFSLinks{links: links, group: group}

	require.NoError(t, batch.Close())
	require.NoError(t, batch.Close())

	commands, err := os.ReadFile(eventsFile)
	require.NoError(t, err)
	assert.Equal(t, "-:obi_abcd/", string(commands))
}

func TestTraceFSLinksFallBackToIndividualRemoval(t *testing.T) {
	eventsFile := filepath.Join(t.TempDir(), "uprobe_events")
	require.NoError(t, os.WriteFile(eventsFile, nil, 0o600))

	links := []*traceFSLink{
		newTestTraceFSLink(t, &traceFSEvent{eventsFile: eventsFile, group: "obi_abcd", name: "probe_0"}),
		newTestTraceFSLink(t, &traceFSEvent{eventsFile: eventsFile, group: "obi_abcd", name: "probe_1"}),
	}
	group := &traceFSEventGroup{eventsFile: t.TempDir(), name: "obi_abcd"}

	require.NoError(t, (&traceFSLinks{links: links, group: group}).Close())

	commands, err := os.ReadFile(eventsFile)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"-:obi_abcd/probe_0", "-:obi_abcd/probe_1"}, splitTraceFSCommands(string(commands)))
}

func newTestTraceFSLink(t *testing.T, event *traceFSEvent) *traceFSLink {
	t.Helper()
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	require.NoError(t, err)
	return &traceFSLink{fd: fd, event: event}
}

func splitTraceFSCommands(commands string) []string {
	const commandPrefix = "-:"
	commands = strings.TrimPrefix(commands, commandPrefix)
	parts := strings.Split(commands, commandPrefix)
	for i := range parts {
		parts[i] = commandPrefix + parts[i]
	}
	return parts
}

func TestTraceFSEventCommand(t *testing.T) {
	for _, tc := range []struct {
		name, target, want string
		ret                bool
	}{
		{name: "uprobe", target: "/proc/123/exe:0x42", want: "p:obi_abcd/probe_0 /proc/123/exe:0x42"},
		{name: "uretprobe", target: "/proc/123/exe:0x42", ret: true, want: "r:obi_abcd/probe_0 /proc/123/exe:0x42"},
		{name: "USDT", target: "/proc/123/exe:0xc0b0(0x18)", want: "p:obi_abcd/probe_0 /proc/123/exe:0xc0b0(0x18)"},
		{name: "kprobe", target: "tcp_sendmsg", want: "p:obi_abcd/probe_0 tcp_sendmsg"},
		{name: "kretprobe default maxactive", target: "tcp_sendmsg", ret: true, want: "r:obi_abcd/probe_0 tcp_sendmsg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, traceFSEventCommand(tc.target, tc.ret, "obi_abcd", "probe_0"))
		})
	}
}

func TestAttachCleansUpPartialBatch(t *testing.T) {
	for _, kind := range []ProbeType{Uprobe, Kprobe} {
		t.Run(string(kind), func(t *testing.T) {
			eventsFile := filepath.Join(t.TempDir(), string(kind)+"_events")
			require.NoError(t, os.WriteFile(eventsFile, nil, 0o600))
			wantErr := errors.New("second attachment failed")
			var first *traceFSLink
			calls := 0
			got, err := attach(nil, Options{Type: kind, Targets: []string{"first", "second"}},
				func(_ *ebpf.Program, _ Options, _ string, group, name string) (*traceFSLink, error) {
					calls++
					if calls == 2 {
						return nil, wantErr
					}
					first = newTestTraceFSLink(t, &traceFSEvent{eventsFile: eventsFile, group: group, name: name})
					return first, nil
				})
			require.ErrorIs(t, err, wantErr)
			assert.Nil(t, got)
			require.NotNil(t, first)
			_, err = unix.FcntlInt(uintptr(first.fd), unix.F_GETFD, 0)
			require.ErrorIs(t, err, unix.EBADF)
			commands, err := os.ReadFile(eventsFile)
			require.NoError(t, err)
			assert.Equal(t, "-:"+first.event.group+"/", string(commands))
		})
	}
}
