// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

type worker interface {
	work() string
}

type workerImpl struct{}

func (*workerImpl) work() string {
	return "done"
}

var implementation worker = &workerImpl{}

func main() {
	fmt.Println(implementation.work())
}
