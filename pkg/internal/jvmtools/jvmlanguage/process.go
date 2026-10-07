// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmlanguage // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvmlanguage"

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const maxProcessBytes = 2 * 1024 * 1024

// DetectPID performs passive Linux /proc inspection. It does not attach to the JVM.
func DetectPID(pid int) (Result, error) {
	if pid <= 0 {
		return Result{}, errors.New("invalid PID")
	}
	proc := "/proc/" + strconv.Itoa(pid)
	executable, err := os.Readlink(proc + "/exe")
	if err != nil || filepath.Base(executable) != "java" {
		return Result{}, errors.New("only standard java launcher processes are supported")
	}
	start, err := processStart(proc)
	if err != nil {
		return Result{}, err
	}
	maps, err := readProcessFile(proc + "/maps")
	if err != nil {
		return Result{}, err
	}
	if !strings.Contains(string(maps), "/libjvm.so") {
		return Result{}, errors.New("process has no observed libjvm.so mapping")
	}
	cmd, err := readProcessFile(proc + "/cmdline")
	if err != nil {
		return Result{}, err
	}
	args := strings.Split(strings.TrimSuffix(string(cmd), "\x00"), "\x00")
	if len(args) < 2 {
		return Result{}, errors.New("missing Java launch arguments")
	}
	environ, err := readProcessFile(proc + "/environ")
	if err != nil {
		return Result{}, err
	}
	env := map[string]string{}
	for value := range strings.SplitSeq(string(environ), "\x00") {
		key, value, ok := strings.Cut(value, "=")
		if ok {
			env[key] = value
		}
	}
	cwd, err := os.Readlink(proc + "/cwd")
	if err != nil {
		return Result{}, err
	}
	result, err := Detect(proc+"/root", cwd, args[1:], env)
	if err != nil {
		return Result{}, err
	}
	after, err := processStart(proc)
	if err != nil || after != start {
		return Result{}, errors.New("process exited or PID was reused during inspection")
	}
	afterCmd, err := readProcessFile(proc + "/cmdline")
	if err != nil || !bytes.Equal(cmd, afterCmd) {
		return Result{}, errors.New("process launch changed during inspection")
	}
	return result, nil
}

func readProcessFile(path string) ([]byte, error) {
	data, _, err := langtools.ReadMetadataFile(path, maxProcessBytes)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("cannot read process metadata %q", path)
	}
	return data, nil
}

func processStart(proc string) (string, error) {
	data, err := readProcessFile(proc + "/stat")
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	const startTimeIndex = 22 - 3 // Fields after comm start at field 3; starttime is field 22.
	if len(fields) <= startTimeIndex {
		return "", errors.New("truncated process stat")
	}
	return fields[startTimeIndex], nil
}
