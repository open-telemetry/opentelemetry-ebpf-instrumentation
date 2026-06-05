// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"strings"
	"testing"
)

func TestGenprotoPinsGrpcGenerator(t *testing.T) {
	script, err := os.ReadFile("genproto.sh")
	if err != nil {
		t.Fatal(err)
	}

	scriptContents := string(script)
	for _, want := range []string{
		"google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2",
		"google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0",
	} {
		if !strings.Contains(scriptContents, want) {
			t.Fatalf("genproto.sh does not pin %q", want)
		}
	}

	stub, err := os.ReadFile("genproto/demo_grpc.pb.go")
	if err != nil {
		t.Fatal(err)
	}

	stubContents := string(stub)
	if !strings.Contains(stubContents, "protoc-gen-go-grpc v1.3.0") {
		t.Fatal("demo_grpc.pb.go was not generated with protoc-gen-go-grpc v1.3.0")
	}
	if strings.Contains(stubContents, "grpc.StaticMethod") {
		t.Fatal("demo_grpc.pb.go should not require grpc.StaticMethod")
	}
}
