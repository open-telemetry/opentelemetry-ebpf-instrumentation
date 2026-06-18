// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import "errors"

func CgroupV2Path() (string, error) { return "", errors.New("cgroupv2 not supported on this platform") }
