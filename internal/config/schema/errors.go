// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import "fmt"

// NotV2Error reports input that does not contain an OBI v2 configuration.
//
// It is distinct from UnsupportedVersionError: NotV2Error means no usable OBI v2
// version marker was found, while UnsupportedVersionError means a version marker
// was found but is not supported by this package.
type NotV2Error struct {
	Reason string
}

func (e *NotV2Error) Error() string {
	if e == nil || e.Reason == "" {
		return "configuration is not OBI config v2"
	}
	return "configuration is not OBI config v2: " + e.Reason
}

func (e *NotV2Error) Is(target error) bool {
	_, ok := target.(*NotV2Error)
	return ok
}

// UnsupportedVersionError reports an OBI v2 version field whose value is present
// but not handled by this package.
type UnsupportedVersionError struct {
	Version string
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("unsupported OBI config version %q", e.Version)
}

// SectionNotAllowedError reports a configuration section that is structurally
// valid OBI v2 but invalid for the selected deployment parser.
type SectionNotAllowedError struct {
	// Mode is the deployment mode whose parser rejected the section.
	Mode string
	// Section is the YAML key that is not allowed in Mode.
	Section string
}

func (e *SectionNotAllowedError) Error() string {
	if e.Mode == string(validationModeReceiver) {
		return fmt.Sprintf(
			"section %q is not allowed in %s mode; remove it from the receiver config or run this config in standalone mode",
			e.Section,
			e.Mode,
		)
	}
	return fmt.Sprintf("section %q is not allowed in %s mode", e.Section, e.Mode)
}
