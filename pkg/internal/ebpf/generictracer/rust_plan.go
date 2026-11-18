// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"fmt"
	"io"

	"go.opentelemetry.io/obi/internal/rustexec"
)

type rustProbeAlternative map[rustProbeKind][]uint64

type rustProbeGroup struct {
	name         string
	feature      string
	alternatives []rustProbeAlternative
}

func planRustProbes(symbols rustProbeSymbols, config BpfRustProtocolConfigT) []rustProbeGroup {
	var groups []rustProbeGroup
	add := func(name, feature string, addresses map[rustProbeKind][]uint64, alternatives ...[]rustProbeKind) {
		group := rustProbeGroup{name: name, feature: feature}

		for _, kinds := range alternatives {
			alternative := rustProbeAlternative{}

			for _, kind := range kinds {
				if len(addresses[kind]) == 0 {
					alternative = nil
					break
				}
				alternative[kind] = addresses[kind]
			}

			if len(alternative) > 0 {
				group.alternatives = append(group.alternatives, alternative)
				if len(group.alternatives) == 3 {
					break
				}
			}
		}

		if len(group.alternatives) > 0 {
			groups = append(groups, group)
		}
	}

	addresses := map[rustProbeKind][]uint64{}
	for kind, offsets := range symbols.addresses {
		addresses[rustProbeKind(kind)] = offsets
	}

	add("Tokio poll", "task-poll", addresses, []rustProbeKind{rustTaskPoll}, []rustProbeKind{rustTaskHarnessPoll})
	add("Tokio deallocation", "task-dealloc", addresses, []rustProbeKind{rustTaskDealloc}, []rustProbeKind{rustTaskHarnessDealloc})
	add("Tokio task binding", "task-create", addresses, []rustProbeKind{rustTaskBind})
	add("Tokio allocation", "task-create", addresses, []rustProbeKind{rustTaskNew}, []rustProbeKind{rustTaskRawNew})
	add("Tokio initial task publication", "task-create", addresses, []rustProbeKind{rustTaskPublish})
	add("Tokio spawn scheduling", "task-create", addresses, []rustProbeKind{rustTaskSpawn, rustTaskSchedule})
	for _, channel := range symbols.channels {
		channelAddresses := symbols.channelProbes[channel]
		channelAddresses[rustHyperRequestReceive] = channelAddresses[rustHyperReceive]
		alternatives := [][]rustProbeKind{{rustHyperEnqueue, rustHyperDequeue}}

		if config.Message&rustexec.MessageCallback != 0 {
			alternatives = append(alternatives, []rustProbeKind{rustHyperChanSend, rustHyperReceive}, []rustProbeKind{rustHyperSend, rustHyperReceive})
		}

		if config.Message&rustexec.MessageList != 0 {
			alternatives = append(alternatives, []rustProbeKind{rustHyperFindBlock, rustHyperPop})
		}

		if config.Message&rustexec.MessageRequest != 0 {
			alternatives = append(alternatives, []rustProbeKind{rustHyperRequestSend, rustHyperRequestReceive})
		}

		add("Hyper channel "+channel, "channel:"+channel, channelAddresses, alternatives...)
	}

	if config.Rustls != 0 {
		add("Rustls client processing", "tls-process", addresses, []rustProbeKind{rustTLSClientProcess}, []rustProbeKind{rustTLSClientLegacyProcess})
		add("Rustls server processing", "tls-process", addresses, []rustProbeKind{rustTLSServerProcess}, []rustProbeKind{rustTLSServerLegacyProcess})

		flush := [][]rustProbeKind{{rustTLSFlush}}
		if config.TlsSendable != 0 {
			flush = append(flush, []rustProbeKind{rustTLSFlushBuffer})
		}

		add("Rustls encrypted I/O binding", "tls-process", addresses, flush...)
		add("Rustls peek/consume", "tls-io", addresses, []rustProbeKind{rustTLSChunk, rustTLSConsume})
		add("Rustls read", "tls-io", addresses, []rustProbeKind{rustTLSRead}, []rustProbeKind{rustTLSReaderRead})
		add("Rustls scalar write", "tls-io", addresses, []rustProbeKind{rustTLSWrite})
		add("Rustls vectored write", "tls-io", addresses, []rustProbeKind{rustTLSWriteVectored})
	}

	if config.Http1 != 0 {
		add("HTTP/1 header formatting", "http1", addresses, []rustProbeKind{rustHTTP1Headers})
		add("HTTP/1 original header casing", "http1", addresses, []rustProbeKind{rustHTTP1HeadersOriginal})
	}

	if config.Http2 != 0 {
		add("HTTP/2 request context", "h2-send", addresses, []rustProbeKind{rustH2SendHeaders})

		var send, prioritize []rustProbeKind
		for _, kind := range []rustProbeKind{rustH2BufferPending, rustH2PollComplete} {
			if len(addresses[kind]) > 0 {
				send = append(send, kind)
			}
		}

		for _, kind := range []rustProbeKind{rustH2PrioritizePending, rustH2PrioritizeComplete} {
			if len(addresses[kind]) > 0 {
				prioritize = append(prioritize, kind)
			}
		}

		add("HTTP/2 connection driver", "h2-driver", addresses, send, prioritize)
		add("HTTP/2 frame encoding", "h2-encode", addresses, []rustProbeKind{rustH2Encode})

		if config.H2Hpack != 0 {
			add("HTTP/2 HPACK encoding", "h2-hpack", addresses, []rustProbeKind{rustH2HPACK})
		}

		if config.H2Server != 0 {
			add("HTTP/2 decoded server requests", "h2-server", addresses, []rustProbeKind{rustH2TakeStreamRequest}, []rustProbeKind{rustH2TakeRequest})
		}
	}

	return groups
}

func planRustChannelClears(symbols rustProbeSymbols, features map[string]bool) []rustProbeGroup {
	var groups []rustProbeGroup
	for _, channel := range symbols.channels {
		if features["channel:"+channel] {
			continue
		}

		var addresses []uint64
		for _, kind := range []rustProbeKind{rustHyperReceive, rustHyperPop, rustHyperDequeue} {
			addresses = append(addresses, symbols.channelProbes[channel][kind]...)
		}

		if len(addresses) > 0 {
			groups = append(groups, rustProbeGroup{
				name:    "Unresolved Hyper channel " + channel,
				feature: "channel-clear:" + channel, alternatives: []rustProbeAlternative{{rustHyperClear: addresses}},
			})
		}
	}

	return groups
}

func attachRustGroups(groups []rustProbeGroup, attach func(rustProbeAlternative) ([]io.Closer, error)) ([]io.Closer, map[string]bool, error) {
	var links []io.Closer
	features := map[string]bool{}
	var failures []error

	for _, group := range groups {
		var lastError error

		for _, alternative := range group.alternatives {
			attached, err := attach(alternative)
			if err != nil {
				for _, closer := range attached {
					_ = closer.Close()
				}
				lastError = err
				continue
			}

			links = append(links, attached...)
			features[group.feature] = true
			lastError = nil
			break
		}

		if lastError != nil {
			failures = append(failures, fmt.Errorf("%s: %w", group.name, lastError))
		}
	}

	return links, features, errors.Join(failures...)
}
