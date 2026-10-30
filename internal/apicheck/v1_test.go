// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package apicheck

import (
	"context"
	"net/http"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/cloud"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/transform"
)

// These assignments protect function values compiled against the v1 signatures.
var _ func(*cilium.Program, cilium.AttachType) (link.Link, error) = ebpf.AttachCgroupSockOps

var _ func(*request.Span, *http.Request, *http.Response, []string) (request.Span, bool) = ebpfhttp.SQLPPSpan

var _ func(*global.ContextInfo, *msg.Queue[exec.ProcessEvent], *msg.Queue[exec.ProcessEvent]) swarm.InstanceFunc = transform.CloudProcessEventDecoratorProvider

var _ func(context.Context, *metadata.NodeMeta, []transform.Source, transform.CloudMetadataConfig) []cloud.MetadataRefresher = transform.CloudMetadataRefreshers

var _ func(*obi.Config, *ebpfcommon.EBPFEventContext, *msg.Queue[[]discover.Event[discover.ProcessAttrs]], []services.Selector, discover.ProcessWatcherRescan) swarm.RunFunc = discover.ProcessWatcherFunc

var _ = ebpfcommon.ProbeDesc{SymbolMatcher: ebpfcommon.SymbolMatcherExact}

var _ ebpfcommon.SymbolMatcher = ebpfcommon.SymbolMatcherContains
