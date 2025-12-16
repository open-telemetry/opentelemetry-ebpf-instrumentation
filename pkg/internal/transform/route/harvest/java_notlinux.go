// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package harvest

type (
	JavaRoutes   struct{ Attacher JavaAttacher }
	JavaAttacher interface {
		Init()
		Cleanup()
	}
)

func NewJavaRoutesHarvester() *JavaRoutes                                  { return nil }
func (h *JavaRoutes) ExtractRoutes(_ int32) (*RouteHarvesterResult, error) { return nil, nil }
