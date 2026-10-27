// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rdns // import "go.opentelemetry.io/obi/pkg/internal/pipe/rdns"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"
	"go.opentelemetry.io/obi/pkg/internal/rdns/store"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	ReverseDNSNone        = "none"
	ReverseDNSLocalLookup = "local"
	ReverseDNSEBPF        = "ebpf"
)

func rdlog() *slog.Logger {
	return slog.With("component", "rdns.ReverseDNS")
}

var netLookupAddr = net.LookupAddr

var startDNSPacketInspector = func(ctx context.Context, dnsCache *store.InMemory, ebpfCfg *config.EBPFTracer) error {
	return xdp.StartDNSPacketInspector(ctx, dnsCache, ebpfCfg)
}

// EBPFLookup shares the eBPF-based reverse DNS between the pipelines of an OBI run,
// as an XDP program can be attached only once per interface.
type EBPFLookup struct {
	ebpfCfg  *config.EBPFTracer
	cacheLen int

	mt         sync.Mutex
	users      int
	stop       context.CancelFunc
	lookupAddr func(string) ([]string, error)
}

// NewEBPFLookup sizes the shared cache with the largest CacheLen of the provided
// eBPF-based reverse DNS configurations.
func NewEBPFLookup(ebpfCfg *config.EBPFTracer, cfgs ...*ReverseDNS) *EBPFLookup {
	l := &EBPFLookup{ebpfCfg: ebpfCfg}
	for _, cfg := range cfgs {
		if cfg.Type == ReverseDNSEBPF {
			l.cacheLen = max(l.cacheLen, cfg.CacheLen)
		}
	}
	return l
}

// acquire starts the DNS packet inspector if it is not running yet.
// The inspector stops when the contexts of all its users are done.
func (l *EBPFLookup) acquire(ctx context.Context) (func(string) ([]string, error), error) {
	l.mt.Lock()
	defer l.mt.Unlock()

	if l.users == 0 {
		if err := l.start(); err != nil {
			return nil, err
		}
	}
	l.users++
	context.AfterFunc(ctx, l.release)

	return l.lookupAddr, nil
}

func (l *EBPFLookup) start() error {
	dnsCache, err := store.NewInMemory(l.cacheLen)
	if err != nil {
		return fmt.Errorf("initializing eBPF-based reverse DNS cache: %w", err)
	}

	// not bound to the first user, as the other users would lose the inspector when it stops
	ctx, cancel := context.WithCancel(context.Background())
	if err := startDNSPacketInspector(ctx, dnsCache, l.ebpfCfg); err != nil {
		cancel()
		return fmt.Errorf("starting eBPF-based reverse DNS: %w", err)
	}

	l.stop = cancel
	l.lookupAddr = dnsCache.GetHostnames
	return nil
}

func (l *EBPFLookup) release() {
	l.mt.Lock()
	defer l.mt.Unlock()

	l.users--
	if l.users == 0 {
		l.stop()
	}
}

// ReverseDNS is currently experimental. It is kept disabled by default and will be hidden
// from the documentation. This means that it does not impact in the overall OBI performance.
type ReverseDNS struct {
	// Type specifies the ReverseDNS method. Values are "none" (default), "local" and "ebpf"
	// It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE for backwards-compatibility
	Type string `yaml:"type" env:"OTEL_EBPF_REVERSE_DNS_TYPE,expand" envDefault:"${OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE}" validate:"oneof=none local ebpf" jsonschema:"type=string,enum=none,enum=local,enum=ebpf"`

	// CacheLen only applies to the "local" and "ebpf" ReverseDNS type. It
	// specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	// It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN for backwards-compatibility
	CacheLen int `yaml:"cache_len" env:"OTEL_EBPF_REVERSE_DNS_CACHE_LEN,expand" envDefault:"${OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN}" validate:"gte=0"`

	// CacheTTL only applies to the "local" and "ebpf" ReverseDNS type. It
	// specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	// It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL for backwards-compatibility
	CacheTTL time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_REVERSE_DNS_CACHE_TTL,expand" envDefault:"${OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL}" validate:"gte=0"`
}

func (r ReverseDNS) Enabled() bool {
	rdType := strings.ToLower(r.Type)
	return rdType == ReverseDNSLocalLookup || rdType == ReverseDNSEBPF
}

func ReverseDNSProvider[T any](cfg *ReverseDNS, attrs func(T) *pipe.CommonAttrs, ebpfLookup *EBPFLookup, input, output *msg.Queue[[]T]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.Bypass(input, output)
		}

		lookupAddr, err := lookupAddrFunc(ctx, cfg, ebpfLookup)
		if err != nil {
			return nil, err
		}
		// TODO: replace by a cache with fuzzy expiration time to avoid cache stampede
		cache := expirable.NewLRU[pipe.IPAddr, string](cfg.CacheLen, nil, cfg.CacheTTL)

		log := rdlog()
		in := input.Subscribe(msg.SubscriberName("rdns.ReverseDNS"))
		return func(_ context.Context) {
			defer output.Close()
			log.Debug("starting reverse DNS node")
			for items := range in {
				for _, item := range items {
					a := attrs(item)
					if a.SrcName == "" {
						a.SrcName = optGetName(log, cache, lookupAddr, a.SrcAddr)
					}
					if a.DstName == "" {
						a.DstName = optGetName(log, cache, lookupAddr, a.DstAddr)
					}
				}
				output.Send(items)
			}
		}, nil
	}
}

// returns the reverse DNS method according to the provided configuration
func lookupAddrFunc(ctx context.Context, cfg *ReverseDNS, ebpfLookup *EBPFLookup) (func(string) ([]string, error), error) {
	if cfg.Type != ReverseDNSEBPF {
		return netLookupAddr, nil
	}
	if ebpfLookup == nil {
		return nil, errors.New("eBPF-based reverse DNS is not available")
	}
	return ebpfLookup.acquire(ctx)
}

func optGetName(
	log *slog.Logger,
	cache *expirable.LRU[pipe.IPAddr, string],
	lookupAddr func(string) ([]string, error),
	ip pipe.IPAddr,
) string {
	if host, ok := cache.Get(ip); ok {
		return host
	}
	ipStr := ip.IP().String()
	if names, err := lookupAddr(ipStr); err == nil && len(names) > 0 {
		cache.Add(ip, names[0])
		return names[0]
	} else if err != nil {
		log.Debug("error trying to lookup by IP address", "ip", ipStr, "error", err)
	}
	// return empty string. In a later pipeline stage it will be decorated with
	// the actual IP
	return ""
}
