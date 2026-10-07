// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmlanguage // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvmlanguage"

import (
	"errors"
	"fmt"
	"strings"
)

type launch struct {
	main   string
	jar    string
	source bool
	vmArgs []string
}

// parseLaunch accepts a deliberately small subset of the Java launcher grammar.
func parseLaunch(args []string, env map[string]string) (launch, error) {
	for _, key := range []string{"JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"} {
		if env[key] != "" {
			return launch{}, fmt.Errorf("unsupported launcher environment: %s", key)
		}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-cp" || arg == "-classpath" || arg == "--class-path":
			if i+1 >= len(args) || args[i+1] == "" {
				return launch{}, fmt.Errorf("missing value for %s", arg)
			}
			i++
		case strings.HasPrefix(arg, "--class-path="):
			if arg == "--class-path=" {
				return launch{}, errors.New("empty explicit classpath is unsupported")
			}
		case arg == "-jar":
			if i+1 >= len(args) {
				return launch{}, errors.New("missing jar path")
			}
			return launch{jar: args[i+1], vmArgs: args[:i+2]}, nil
		case strings.HasPrefix(arg, "-D"):
			if strings.HasPrefix(arg, "-Djava.system.class.loader") || strings.HasPrefix(arg, "-Dloader.") || strings.HasPrefix(arg, "-Djava.class.path") || strings.HasPrefix(arg, "-Dsun.boot.class.path") {
				return launch{}, fmt.Errorf("unsupported class loader option %q", arg)
			}
		case strings.HasPrefix(arg, "-Xmx"), strings.HasPrefix(arg, "-Xms"), strings.HasPrefix(arg, "-Xss"), arg == "-server", arg == "-client", arg == "-ea", arg == "-da":
		case strings.HasPrefix(arg, "-"), strings.HasPrefix(arg, "@"):
			return launch{}, fmt.Errorf("unsupported launcher option %q", arg)
		default:
			if arg == "" {
				return launch{}, errors.New("empty entry point")
			}
			return launch{main: arg, source: strings.HasSuffix(arg, ".java"), vmArgs: args[:i]}, nil
		}
	}
	return launch{}, errors.New("missing entry point")
}
