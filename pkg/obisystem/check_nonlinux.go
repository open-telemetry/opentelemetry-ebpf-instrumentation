// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package obisystem

var CheckSupport = func() error {
	return nil
}

func CheckCapabilities(_ CapabilityConfig) error {
	return nil
}

func KernelVersion() (major, minor int) {
	return 5, 17
}
