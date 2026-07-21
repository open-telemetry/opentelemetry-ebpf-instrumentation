// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

const (
	defaultHotReloadPollInterval = 15 * time.Second
	configMapDataKey             = "config.yaml"
)

// ConfigMapWatcher watches Kubernetes ConfigMaps for discovery criteria changes
// and atomically updates the dynamic criteria pointer used by the Matcher.
type ConfigMapWatcher struct {
	kubeClient      kubernetes.Interface
	namespace       string
	configMapNames  []string
	pollInterval    time.Duration
	dynamicCriteria *atomic.Pointer[[]services.Selector]
	rescanCh        chan<- struct{}
	lastHash        string
	lastServices    map[string]struct{}
	log             *slog.Logger
}

// NewConfigMapWatcher creates a watcher that polls the specified ConfigMaps for discovery
// instrument criteria and stores updates in the given atomic pointer.
// rescanCh is signaled after criteria update to trigger ProcessWatcher full re-scan.
func NewConfigMapWatcher(
	kubeClient kubernetes.Interface,
	namespace string,
	configMapNames []string,
	pollInterval time.Duration,
	target *atomic.Pointer[[]services.Selector],
	rescanCh chan<- struct{},
) *ConfigMapWatcher {
	if pollInterval <= 0 {
		pollInterval = defaultHotReloadPollInterval
	}
	return &ConfigMapWatcher{
		kubeClient:      kubeClient,
		namespace:       namespace,
		configMapNames:  configMapNames,
		pollInterval:    pollInterval,
		dynamicCriteria: target,
		rescanCh:        rescanCh,
		log:             slog.With("component", "discover.ConfigMapWatcher"),
	}
}

// Start begins polling ConfigMaps. It blocks until ctx is cancelled.
func (w *ConfigMapWatcher) Start(ctx context.Context) {
	w.log.Info("starting ConfigMap watcher for discovery hot-reload",
		"namespace", w.namespace, "configmaps", w.configMapNames, "interval", w.pollInterval)

	// initial load
	w.reload(ctx)

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.log.Debug("ConfigMap watcher stopping")
			return
		case <-ticker.C:
			w.reload(ctx)
		}
	}
}

func (w *ConfigMapWatcher) reload(ctx context.Context) {
	var allCriteria services.GlobDefinitionCriteria
	var rawContents []string

	for _, name := range w.configMapNames {
		cm, err := w.kubeClient.CoreV1().ConfigMaps(w.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			w.log.Warn("failed to get ConfigMap", "name", name, "namespace", w.namespace, "error", err)
			continue
		}

		raw, ok := cm.Data[configMapDataKey]
		if !ok {
			keys := make([]string, 0, len(cm.Data))
			for k := range cm.Data {
				keys = append(keys, k)
			}
			w.log.Warn("ConfigMap has no expected data key", "name", name, "expected_key", configMapDataKey, "available_keys", keys)
			continue
		}

		rawContents = append(rawContents, raw)
		criteria := parseDiscoveryInstrument(raw)
		w.log.Debug("parsed ConfigMap", "name", name, "raw_length", len(raw), "criteria_count", len(criteria))
		if len(criteria) > 0 {
			allCriteria = append(allCriteria, criteria...)
		}
	}

	hash := contentHash(rawContents)
	if hash == w.lastHash {
		return
	}
	w.lastHash = hash

	if len(allCriteria) == 0 {
		w.log.Info("ConfigMap hot-reload: no instrument criteria found, clearing dynamic criteria")
		if len(w.lastServices) > 0 {
			for svc := range w.lastServices {
				w.log.Warn("ConfigMap hot-reload: service removed", "service", svc)
			}
		}
		w.lastServices = nil
		empty := make([]services.Selector, 0)
		w.dynamicCriteria.Store(&empty)
		w.triggerRescan()
		return
	}

	selectors := NormalizeGlobCriteria(allCriteria)
	w.dynamicCriteria.Store(&selectors)

	currentServices := criteriaServiceNames(allCriteria)
	w.logServiceChanges(currentServices)
	w.lastServices = currentServices

	w.log.Info("ConfigMap hot-reload: updated dynamic discovery criteria",
		"count", len(selectors), "services", serviceSetKeys(currentServices))
	w.triggerRescan()
}

func (w *ConfigMapWatcher) triggerRescan() {
	if w.rescanCh == nil {
		return
	}
	select {
	case w.rescanCh <- struct{}{}:
	default:
		// channel already has a pending signal, skip
	}
}

// discoveryConfigFragment is a minimal struct for unmarshalling only the discovery.instrument section
type discoveryConfigFragment struct {
	Discovery struct {
		Instrument services.GlobDefinitionCriteria `yaml:"instrument"`
	} `yaml:"discovery"`
}

func parseDiscoveryInstrument(raw string) services.GlobDefinitionCriteria {
	var fragment discoveryConfigFragment
	if err := yaml.Unmarshal([]byte(raw), &fragment); err != nil {
		slog.Warn("ConfigMap hot-reload: failed to parse YAML", "error", err)
		return nil
	}
	return fragment.Discovery.Instrument
}

func contentHash(contents []string) string {
	sort.Strings(contents)
	h := sha256.New()
	for _, c := range contents {
		fmt.Fprintf(h, "%s\n", strings.TrimSpace(c))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func criteriaServiceNames(criteria services.GlobDefinitionCriteria) map[string]struct{} {
	names := make(map[string]struct{}, len(criteria))
	for i := range criteria {
		name := criteriaDisplayName(&criteria[i])
		names[name] = struct{}{}
	}
	return names
}

func criteriaDisplayName(ga *services.GlobAttributes) string {
	if ga.Name != "" {
		return ga.Name
	}
	var parts []string
	for k := range ga.Metadata {
		parts = append(parts, k)
	}
	if len(parts) > 0 {
		sort.Strings(parts)
		return strings.Join(parts, ",")
	}
	return "<unnamed>"
}

func (w *ConfigMapWatcher) logServiceChanges(current map[string]struct{}) {
	for svc := range current {
		if _, ok := w.lastServices[svc]; !ok {
			w.log.Warn("ConfigMap hot-reload: service added", "service", svc)
		}
	}
	for svc := range w.lastServices {
		if _, ok := current[svc]; !ok {
			w.log.Warn("ConfigMap hot-reload: service removed", "service", svc)
		}
	}
}

func serviceSetKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
