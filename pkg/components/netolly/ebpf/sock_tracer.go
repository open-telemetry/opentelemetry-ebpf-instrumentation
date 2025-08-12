// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/containers/common/pkg/cgroupv2"

	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t  -type flow_record_t -target amd64,arm64 NetSk ../../../../bpf/netolly/flows_sock.c -- -I../../../../bpf

type SockFlowFetcher struct {
	log           *slog.Logger
	objects       *NetSkObjects
	ringbufReader *ringbuf.Reader
	links         []link.Link
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.FlowFetcher")
}

func getCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := cgroupv2.Enabled()
	if !enabled {
		if _, pathErr := os.Stat(filepath.Join(cgroupPath, "unified")); pathErr == nil {
			slog.Debug("discovered hybrid cgroup hierarchy, will attempt to attach sockops")
			return filepath.Join(cgroupPath, "unified"), nil
		}
		return "", errors.New("failed to find unified cgroup hierarchy: sockops cannot be used with cgroups v1")
	}
	return cgroupPath, err
}

func attachCgroup(program *ebpf.Program, attachType ebpf.AttachType) (link.Link, error) {
	cgroupPath, err := getCgroupPath()

	if err != nil {
		return nil, fmt.Errorf("error getting cgroup path: %w", err)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  attachType,
		Program: program,
	})

	if err != nil {
		return nil, fmt.Errorf("attaching cgroup program: %w", err)
	}

	return l, nil
}

func NewSockFlowFetcher() (*SockFlowFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := NetSkObjects{}
	spec, err := LoadNetSk()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 640 * 1024},
	}); err != nil {
		printVerifierErrorInfo(err)
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	links := []link.Link{}

	lnk, err := attachCgroup(objects.ObiSockEgress, ebpf.AttachCGroupInetEgress)

	if err != nil {
		return nil, fmt.Errorf("error attaching cgroup program: %w", err)
	}

	links = append(links, lnk)

	lnk, err = attachCgroup(objects.ObiSockIngress, ebpf.AttachCGroupInetIngress)

	if err != nil {
		return nil, fmt.Errorf("error attaching cgroup program: %w", err)
	}

	links = append(links, lnk)

	lnk, err = attachCgroup(objects.ObiSockRelease, ebpf.AttachCgroupInetSockRelease)

	if err != nil {
		return nil, fmt.Errorf("error attaching cgroup program: %w", err)
	}

	links = append(links, lnk)

	lnk, err = attachCgroup(objects.ObiSockOps, ebpf.AttachCGroupSockOps)

	if err != nil {
		return nil, fmt.Errorf("error attaching cgroup program: %w", err)
	}

	links = append(links, lnk)

	// read events from socket filter ringbuffer
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	return &SockFlowFetcher{
		log:           tlog,
		objects:       &objects,
		ringbufReader: flows,
		links:         links,
	}, nil
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

// Close any resources that are taken up by the socket filter, the filter itself and some maps.
func (m *SockFlowFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	for _, l := range m.links {
		l.Close()
	}

	var errs []error
	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.objects != nil {
		if err := m.objects.DirectFlows.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (m *SockFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

func (m *SockFlowFetcher) RingBufReader() *ringbuf.Reader {
	return m.ringbufReader
}
