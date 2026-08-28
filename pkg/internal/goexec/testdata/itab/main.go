// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type worker interface {
	work() string
}

type workerImpl struct{}

func (*workerImpl) work() string {
	return "done"
}

var implementation worker = &workerImpl{}
var spanOption trace.SpanStartOption = trace.WithAttributes(attribute.String("key", "value"))
var stringError error = errors.New("test")

func main() {
	fmt.Println(implementation.work())
	_, _ = spanOption, stringError
}
