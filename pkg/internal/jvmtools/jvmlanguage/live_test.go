// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvmlanguage_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// This opt-in suite runs real JVMs and the built CLI, including OBI resource export.
func TestLivePoC(t *testing.T) {
	fixtures := os.Getenv("OBI_JVM_FIXTURES")
	if fixtures == "" {
		t.Skip("set OBI_JVM_FIXTURES to run compiler-produced fixtures")
	}
	compilers := os.Getenv("JVM_RESEARCH_COMPILERS")
	binary := os.Getenv("OBI_JVM_POC_BINARY")
	if compilers == "" || binary == "" {
		t.Fatal("set JVM_RESEARCH_COMPILERS and OBI_JVM_POC_BINARY")
	}
	classes := filepath.Join(fixtures, "classes")
	kotlinCP := classes + ":" + filepath.Join(compilers, "kotlin-stdlib-2.2.20.jar")
	scalaCP := ":" + classes + ":" + filepath.Join(compilers, "scala-library-2.13.16.jar")
	source, err := filepath.Abs("../../../../internal/test/tools/jvm-language-research/JavaSource.java")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, language string
		args           []string
	}{
		{name: "java", args: []string{"-cp", classes, "JavaPlain"}},
		{name: "java source launch", language: "java", args: []string{source}},
		{name: "java with kotlin dependency", args: []string{"-cp", kotlinCP, "JavaPlain"}},
		{name: "java calls kotlin", args: []string{"-cp", kotlinCP, "JavaEntry"}},
		{name: "kotlin calls java", language: "kotlin", args: []string{"-cp", kotlinCP, "KotlinEntriesKt"}},
		{name: "kotlin object", language: "kotlin", args: []string{"-cp", kotlinCP, "ObjectEntry"}},
		{name: "kotlin companion", language: "kotlin", args: []string{"-cp", kotlinCP, "CompanionEntry"}},
		{name: "scala2", language: "scala", args: []string{"-cp", filepath.Join(fixtures, "scala2") + scalaCP, "ScalaEntry"}},
		{name: "scala3", language: "scala", args: []string{"-cp", filepath.Join(fixtures, "scala3") + scalaCP + ":" + filepath.Join(compilers, "scala3-library_3-3.3.6.jar"), "ScalaEntry"}},
		{name: "decoy strings", args: []string{"-cp", classes, "JavaDecoy"}},
		{name: "application argument boundary", language: "kotlin", args: []string{"-cp", kotlinCP, "KotlinEntriesKt", "-jar", "application-argument.jar"}},
		{name: "executable jar", language: "kotlin", args: []string{"-jar", filepath.Join(fixtures, "kotlin.jar")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("java", append([]string{"-Dobi.research.wait=60000"}, tt.args...)...)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				if stderr.Len() > 0 {
					t.Log(stderr.String())
				}
			})
			ready := make(chan bool, 1)
			go func() { ready <- bufio.NewScanner(stdout).Scan() }()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatal("JVM exited before fixture readiness")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("JVM startup timed out")
			}
			output, err := exec.Command(binary, strconv.Itoa(cmd.Process.Pid)).CombinedOutput()
			if err != nil {
				t.Fatalf("CLI failed: %v\n%s", err, output)
			}
			var result struct {
				Resource map[string]string `json:"resource"`
				Error    string            `json:"error"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatal(err)
			}
			if result.Error != "" || result.Resource["jvm.language"] != tt.language || result.Resource["telemetry.sdk.language"] != "java" {
				t.Fatalf("unexpected attributes: %s", output)
			}
			if _, exists := result.Resource["jvm.language"]; tt.language == "" && exists {
				t.Fatal("unresolved language must be omitted")
			}
			t.Log(string(output))
		})
	}
}
