package integration

import (
	"path"

	"go.opentelemetry.io/obi/test/tools"
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)
