// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"syscall"

	"github.com/grafana/jvmtools/jvm"
)

var jvmAttachFunc = jvm.Jattach
var jvmAttachInitFunc = initAttach
var jvmAttachCleanupFunc = cleanupAttach

func initAttach() (int, int) {
	myUID := syscall.Geteuid()
	myGID := syscall.Getegid()

	return myUID, myGID
}

func cleanupAttach(myUID, myGID int) error {
	if err := syscall.Setegid(int(myUID)); err != nil {
		return err
	}
	if err := syscall.Seteuid(int(myGID)); err != nil {
		return err
	}

	return nil
}
