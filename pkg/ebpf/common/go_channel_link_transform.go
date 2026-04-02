// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type channelLinkTrace struct {
	Type         uint8
	_            [7]byte
	SpanTp       channelLinkTP
	LinkedSpanTp channelLinkTP
}

type channelLinkTP struct {
	TraceId  [16]byte
	SpanId   [8]byte
	ParentId [8]byte
	Ts       uint64
	Flags    uint8
	_        [7]byte
}

const (
	maxPendingSpanLinks = 1024
	pendingSpanLinksTTL = 5 * time.Minute
	maxLinksPerSpan     = 8
)

type spanLinkKey struct {
	traceID trace.TraceID
	spanID  trace.SpanID
}

type pendingSpanLinks struct {
	cache *expirable.LRU[spanLinkKey, []request.SpanLink]
}

func newPendingSpanLinks() *pendingSpanLinks {
	return &pendingSpanLinks{
		cache: expirable.NewLRU[spanLinkKey, []request.SpanLink](
			maxPendingSpanLinks,
			nil,
			pendingSpanLinksTTL,
		),
	}
}

func readGoChannelLinkEvent(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	if parseCtx == nil || parseCtx.pendingSpanLinks == nil {
		return request.Span{}, true, nil
	}

	event, err := ReinterpretCast[channelLinkTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	parseCtx.pendingSpanLinks.recordPair(
		tpToSpanLinkKey(&event.SpanTp),
		tpToSpanLink(&event.LinkedSpanTp),
	)
	parseCtx.pendingSpanLinks.recordPair(
		tpToSpanLinkKey(&event.LinkedSpanTp),
		tpToSpanLink(&event.SpanTp),
	)

	return request.Span{}, true, nil
}

func (ctx *EBPFParseContext) consumePendingSpanLinks(span *request.Span) {
	if ctx == nil || ctx.pendingSpanLinks == nil || span == nil {
		return
	}

	if !span.TraceID.IsValid() || !span.SpanID.IsValid() {
		return
	}

	ctx.pendingSpanLinks.consume(span)
}

func tpToSpanLinkKey(tp *channelLinkTP) spanLinkKey {
	return spanLinkKey{
		traceID: trace.TraceID(tp.TraceId),
		spanID:  trace.SpanID(tp.SpanId),
	}
}

func tpToSpanLink(tp *channelLinkTP) request.SpanLink {
	return request.SpanLink{
		TraceID:    trace.TraceID(tp.TraceId),
		SpanID:     trace.SpanID(tp.SpanId),
		TraceFlags: tp.Flags,
	}
}

func (p *pendingSpanLinks) recordPair(key spanLinkKey, link request.SpanLink) {
	if p == nil || p.cache == nil {
		return
	}

	if !key.traceID.IsValid() || !key.spanID.IsValid() || !link.TraceID.IsValid() || !link.SpanID.IsValid() {
		return
	}

	links, _ := p.cache.Get(key)
	for _, existing := range links {
		if existing.TraceID == link.TraceID && existing.SpanID == link.SpanID {
			return
		}
	}

	if len(links) >= maxLinksPerSpan {
		return
	}

	links = append(links, link)
	p.cache.Add(key, links)
}

func (p *pendingSpanLinks) consume(span *request.Span) {
	if p == nil || p.cache == nil || span == nil {
		return
	}

	key := spanLinkKey{
		traceID: span.TraceID,
		spanID:  span.SpanID,
	}

	links, ok := p.cache.Get(key)
	if !ok || len(links) == 0 {
		return
	}

	for _, link := range links {
		duplicate := false
		for _, existing := range span.Links {
			if existing.TraceID == link.TraceID && existing.SpanID == link.SpanID {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		span.Links = append(span.Links, link)
	}

	p.cache.Remove(key)
}
