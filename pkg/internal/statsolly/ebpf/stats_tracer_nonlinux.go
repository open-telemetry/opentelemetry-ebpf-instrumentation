// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type StatsFetcher struct{}

func NewStatsFetcher() (*StatsFetcher, error) {
	return nil, nil
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	return nil
}

func (m *StatsFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return ringbuf.Record{}, nil
}
