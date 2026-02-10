// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
Ebpf-instrument automatically instruments applications using eBPF.

Deprecated: This binary has been renamed to "obi" for consistency with the
project name. The ebpf-instrument binary will be removed in a future release.
Please use the "obi" binary (cmd/obi) instead.

Migration: Simply replace any references to "ebpf-instrument" with "obi".
All functionality remains identical. Configuration, command-line flags,
and behavior are unchanged between the two binaries.

Example:

	// Old command
	./ebpf-instrument --config=config.yml

	// New command
	./obi --config=config.yml

For more information, see https://opentelemetry.io/docs/zero-code/obi/
*/
package main
