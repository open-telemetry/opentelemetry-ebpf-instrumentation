// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"log/slog"
	"time"
	"strings"

	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/components/transform/route"
)

type RouteHarvester struct {
	log     *slog.Logger
	java    *JavaRoutes
	disabled map[svc.InstrumentableType]struct{}
	timeout time.Duration

	// testing related
	javaExtractRoutes func(pid int32) (*RouteHarvesterResult, error)
}

type RouteHarvesterResultKind uint8

const (
	CompleteRoutes RouteHarvesterResultKind = iota + 1
	PartialRoutes
)

type RouteHarvesterResult struct {
	Routes []string
	Kind   RouteHarvesterResultKind
}

// HarvestError represents an error that occurred during route harvesting
type HarvestError struct {
	Message string
}

func (e *HarvestError) Error() string {
	return e.Message
}

func NewRouteHarvester(disabled []string, timeout time.Duration) *RouteHarvester {
	dMap := map[svc.InstrumentableType]struct{}{}
	for _, lang := range disabled {
		if strings.ToLower(lang) == "java" {
			dMap[svc.InstrumentableJava] = struct{}{}
		}
	}

	h := &RouteHarvester{
		log:     slog.With("component", "route.harvester"),
		java:    NewJavaRoutesHarvester(),
		disabled: dMap,
		timeout: timeout,
	}

	h.javaExtractRoutes = h.java.ExtractRoutes

	return h
}

func (h *RouteHarvester) HarvestRoutes(fileInfo *exec.FileInfo) (*RouteHarvesterResult, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	// Channel to receive the result
	resultChan := make(chan *RouteHarvesterResult, 1)
	errorChan := make(chan error, 1)

	// Run the harvesting in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				h.log.Error("route harvesting failed", "error", r)
				errorChan <- &HarvestError{Message: "harvesting failed"}
			}
		}()

		if fileInfo.Service.SDKLanguage == svc.InstrumentableJava {
    		if _, ok := h.disabled[svc.InstrumentableJava]; !ok {
	    		result, err := h.javaExtractRoutes(fileInfo.Pid)
                if err != nil {
                    errorChan <- err
                    return
                }
    			resultChan <- result
    		} else {
    		    resultChan <- nil
    		}
		} else {
			resultChan <- nil
		}
	}()

	// Wait for either completion or timeout
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	case <-ctx.Done():
		h.log.Warn("route harvesting timed out", "timeout", h.timeout, "pid", fileInfo.Pid)
		return nil, &HarvestError{Message: "route harvesting timed out"}
	}
}

func RouteMatcherFromResult(r RouteHarvesterResult) route.Matcher {
	switch r.Kind {
	case CompleteRoutes:
		return route.NewMatcher(r.Routes)
	case PartialRoutes:
		return route.NewPartialRouteMatcher(r.Routes)
	}

	return nil
}
