// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

// CaptureRuntimes groups language runtime capture settings.
type CaptureRuntimes struct {
	Go     Runtime     `yaml:"go"`
	NodeJS Runtime     `yaml:"nodejs"`
	Java   JavaRuntime `yaml:"java"`
}

// Runtime describes generic language runtime capture settings.
type Runtime struct {
	Enabled bool             `yaml:"enabled"`
	Filter  AttributeFilters `yaml:"filter,omitempty"`
}

// JavaRuntime describes Java runtime capture and debug settings.
type JavaRuntime struct {
	Enabled       bool              `yaml:"enabled"`
	Filter        AttributeFilters  `yaml:"filter,omitempty"`
	Debug         JavaDebug         `yaml:"debug"`
	AttachTimeout Duration          `yaml:"attach_timeout"`
	DynamicSpans  []JavaDynamicSpan `yaml:"dynamic_spans,omitempty"`
}

// JavaDynamicSpan describes a named span selected by a Java method's class and
// method name globs. This is declarative data only; parsing it does not apply
// instrumentation to a running JVM.
type JavaDynamicSpan struct {
	Name     string             `yaml:"name"`
	Selector JavaMethodSelector `yaml:"selector"`
}

// JavaMethodSelector selects methods by class-name and method-name globs.
type JavaMethodSelector struct {
	ClassGlob  string `yaml:"class_glob"`
	MethodGlob string `yaml:"method_glob"`
}

// JavaDebug describes Java runtime debug instrumentation settings.
type JavaDebug struct {
	Enabled                 bool `yaml:"enabled"`
	BytecodeInstrumentation bool `yaml:"bytecode_instrumentation"`
}
