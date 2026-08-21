// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools // import "go.opentelemetry.io/obi/pkg/internal/nodejstools"

import (
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// NodeLaunch contains the application entrypoint parsed from a Node.js command line.
type NodeLaunch struct {
	EntryPoint string
}

var optionsWithValues = map[string]struct{}{
	"-C":                                  {},
	"-r":                                  {},
	"--allow-fs-read":                     {},
	"--allow-fs-write":                    {},
	"--build-sea":                         {},
	"--build-snapshot-config":             {},
	"--conditions":                        {},
	"--cpu-prof-dir":                      {},
	"--cpu-prof-interval":                 {},
	"--cpu-prof-name":                     {},
	"--debug-port":                        {},
	"--diagnostic-dir":                    {},
	"--disable-proto":                     {},
	"--disable-warning":                   {},
	"--dns-result-order":                  {},
	"--env-file":                          {},
	"--env-file-if-exists":                {},
	"--experimental-config-file":          {},
	"--experimental-default-type":         {},
	"--experimental-loader":               {},
	"--experimental-package-map":          {},
	"--experimental-policy":               {},
	"--experimental-sea-config":           {},
	"--experimental-specifier-resolution": {},
	"--experimental-test-isolation":       {},
	"--experimental-test-tag-filter":      {},
	"--heap-prof-dir":                     {},
	"--heap-prof-interval":                {},
	"--heap-prof-name":                    {},
	"--heapsnapshot-near-heap-limit":      {},
	"--heapsnapshot-signal":               {},
	"--http-parser":                       {},
	"--icu-data-dir":                      {},
	"--import":                            {},
	"--input-type":                        {},
	"--inspect-port":                      {},
	"--inspect-publish-uid":               {},
	"--loader":                            {},
	"--localstorage-file":                 {},
	"--max-http-header-size":              {},
	"--max-old-space-size-percentage":     {},
	"--network-family-autoselection-attempt-timeout": {},
	"--openssl-config":            {},
	"--policy-integrity":          {},
	"--redirect-warnings":         {},
	"--report-dir":                {},
	"--report-directory":          {},
	"--report-filename":           {},
	"--report-signal":             {},
	"--require":                   {},
	"--secure-heap":               {},
	"--secure-heap-min":           {},
	"--security-revert":           {},
	"--snapshot-blob":             {},
	"--test-concurrency":          {},
	"--test-coverage-branches":    {},
	"--test-coverage-exclude":     {},
	"--test-coverage-functions":   {},
	"--test-coverage-include":     {},
	"--test-coverage-lines":       {},
	"--test-global-setup":         {},
	"--test-isolation":            {},
	"--test-name-pattern":         {},
	"--test-random-seed":          {},
	"--test-reporter":             {},
	"--test-reporter-destination": {},
	"--test-rerun-failures":       {},
	"--test-shard":                {},
	"--test-skip-pattern":         {},
	"--test-timeout":              {},
	"--title":                     {},
	"--tls-cipher-list":           {},
	"--tls-keylog":                {},
	"--trace-event-categories":    {},
	"--trace-event-file-pattern":  {},
	"--trace-require-module":      {},
	"--unhandled-rejections":      {},
	"--use-largepages":            {},
	"--v8-pool-size":              {},
	"--watch-kill-signal":         {},
	"--watch-path":                {},
}

// ParseNodeLaunch finds the application entrypoint in a Node.js command line.
func ParseNodeLaunch(args []string) NodeLaunch {
	inspect := false
	entryURL := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if arg == "--" {
			if i+1 < len(args) {
				return launchForEntryPoint(args[i+1], inspect, entryURL)
			}
			return NodeLaunch{}
		}
		if noFileLaunch(arg) || arg == "-" {
			return NodeLaunch{}
		}
		if arg == "--entry-url" {
			entryURL = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if consumesNextArg(arg) {
				i++
			}
			continue
		}
		if !inspect && arg == "inspect" {
			inspect = true
			continue
		}
		return launchForEntryPoint(arg, inspect, entryURL)
	}

	return NodeLaunch{}
}

func noFileLaunch(arg string) bool {
	if arg == "-e" || arg == "--eval" || arg == "-p" || arg == "--print" || arg == "--run" {
		return true
	}
	return strings.HasPrefix(arg, "-e") ||
		strings.HasPrefix(arg, "-p") ||
		strings.HasPrefix(arg, "--eval=") ||
		strings.HasPrefix(arg, "--print=") ||
		strings.HasPrefix(arg, "--run=")
}

func consumesNextArg(arg string) bool {
	if len(arg) > 2 && (strings.HasPrefix(arg, "-r") || strings.HasPrefix(arg, "-C")) {
		return false
	}
	arg = strings.ReplaceAll(arg, "_", "-")
	_, ok := optionsWithValues[arg]
	return ok
}

func launchForEntryPoint(entryPoint string, inspect, entryURL bool) NodeLaunch {
	if inspect && isInspectorAddress(entryPoint) {
		return NodeLaunch{}
	}
	if entryURL {
		parsed, err := url.Parse(entryPoint)
		if err != nil || parsed.Scheme != "file" || parsed.Path == "" ||
			(parsed.Host != "" && parsed.Host != "localhost") {
			return NodeLaunch{}
		}
		entryPoint = filepath.FromSlash(parsed.Path)
	}
	return NodeLaunch{EntryPoint: entryPoint}
}

func isInspectorAddress(value string) bool {
	if port, err := strconv.Atoi(value); err == nil && port > 0 {
		return true
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0
}
