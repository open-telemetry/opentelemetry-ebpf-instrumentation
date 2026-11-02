// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

var _ func(*obi.Config, *ebpfcommon.EBPFEventContext, *msg.Queue[[]discover.Event[discover.ProcessAttrs]], []services.Selector, discover.ProcessWatcherRescan) swarm.RunFunc = discover.ProcessWatcherFunc

func TestProcessWatcherWithV1Arguments(t *testing.T) {
	output := msg.NewQueue[[]discover.Event[discover.ProcessAttrs]]()
	run := discover.ProcessWatcherFunc(&obi.DefaultConfig, nil, output, nil, discover.ProcessWatcherRescan{})
	require.NotNil(t, run)
}
