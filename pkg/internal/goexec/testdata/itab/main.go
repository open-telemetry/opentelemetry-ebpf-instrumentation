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

type arrayWorker [1]byte
type chanWorker chan int
type funcWorker func()
type mapWorker map[string]int
type scalarWorker int
type sliceWorker []byte
type structWorker struct{}

func (arrayWorker) work() string  { return "array" }
func (chanWorker) work() string   { return "chan" }
func (funcWorker) work() string   { return "func" }
func (mapWorker) work() string    { return "map" }
func (scalarWorker) work() string { return "scalar" }
func (sliceWorker) work() string  { return "slice" }
func (structWorker) work() string { return "struct" }

var implementations = []worker{
	&workerImpl{},
	arrayWorker{},
	chanWorker(nil),
	funcWorker(nil),
	mapWorker(nil),
	scalarWorker(0),
	sliceWorker(nil),
	structWorker{},
}
var spanOption trace.SpanStartOption = trace.WithAttributes(attribute.String("key", "value"))
var stringError error = errors.New("test")

func main() {
	for _, implementation := range implementations {
		fmt.Println(implementation.work())
	}
	_, _ = spanOption, stringError
}
