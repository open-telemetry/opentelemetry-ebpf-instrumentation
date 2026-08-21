// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools // import "go.opentelemetry.io/obi/pkg/internal/nodejstools"

import "strings"

// NodeLaunch contains the application entrypoint parsed from a Node.js command line.
type NodeLaunch struct {
	EntryPoint string
}

// ParseNodeLaunch finds the application entrypoint in a Node.js command line.
func ParseNodeLaunch(args []string) NodeLaunch {
	skipNext := false
	optionsEnded := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if !optionsEnded {
			if arg == "--" {
				optionsEnded = true
				continue
			}
			if nodeOptionConsumesScriptArgument(arg) {
				skipNext = true
				continue
			}
			if strings.HasPrefix(arg, "-") {
				continue
			}
		}
		if hasNodeScriptExtension(arg) {
			return NodeLaunch{EntryPoint: arg}
		}
	}
	return NodeLaunch{}
}

func nodeOptionConsumesScriptArgument(arg string) bool {
	switch arg {
	case "-e", "--eval", "-p", "--print", "--run", "--entry-url",
		"-r", "--require", "--import", "--loader", "--experimental-loader":
		return true
	default:
		return false
	}
}

func hasNodeScriptExtension(arg string) bool {
	return strings.HasSuffix(arg, ".js") ||
		strings.HasSuffix(arg, ".mjs") ||
		strings.HasSuffix(arg, ".cjs") ||
		strings.HasSuffix(arg, ".ts")
}
