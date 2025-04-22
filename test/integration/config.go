package integration

import (
	"path"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/tools"
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)
