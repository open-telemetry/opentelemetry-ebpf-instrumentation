// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import "go.opentelemetry.io/obi/pkg/internal/netns"

func withNetNS(hostPid int, fn func() error) error {
	return netns.WithNetNS(hostPid, fn)
}
