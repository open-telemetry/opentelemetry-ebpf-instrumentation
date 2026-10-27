// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javadynamic

import "testing"

func TestParseFunctionReference(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want FunctionReference
	}{
		{
			name: "exact class and method",
			ref:  "io.opentelemetry.PolicyProvider#create",
			want: FunctionReference{ClassSelector: "io.opentelemetry.PolicyProvider", MethodSelector: "create"},
		},
		{
			name: "class and method globs with parameters",
			ref:  "com.example.*Repository#find?By*(java.lang.String,int[])",
			want: FunctionReference{
				ClassSelector: "com.example.*Repository", MethodSelector: "find?By*",
				ClassGlob: true, MethodGlob: true, HasParameters: true,
				Parameters: []string{"java.lang.String", "int[]"},
			},
		},
		{
			name: "empty parameter list",
			ref:  "com.example.Service#start()",
			want: FunctionReference{ClassSelector: "com.example.Service", MethodSelector: "start", HasParameters: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseFunctionReference(test.ref)
			if err != nil {
				t.Fatal(err)
			}
			if got.ClassSelector != test.want.ClassSelector || got.MethodSelector != test.want.MethodSelector ||
				got.ClassGlob != test.want.ClassGlob || got.MethodGlob != test.want.MethodGlob ||
				got.HasParameters != test.want.HasParameters || len(got.Parameters) != len(test.want.Parameters) {
				t.Fatalf("ParseFunctionReference(%q) = %#v, want %#v", test.ref, got, test.want)
			}
			for i := range got.Parameters {
				if got.Parameters[i] != test.want.Parameters[i] {
					t.Fatalf("parameter %d = %q, want %q", i, got.Parameters[i], test.want.Parameters[i])
				}
			}
		})
	}
}

func TestParseFunctionReferenceRejectsInvalidReferences(t *testing.T) {
	for _, ref := range []string{
		"",
		"Service#run",
		"com.example.Service##run",
		"com.example.Service#run()tail",
		"com.example.Service#run(int,,long)",
		"com.example.Service#run(String)",
		"com.example.Service#run(void)",
		"com..example.Service#run",
		"com.example.Service#run (int)",
	} {
		t.Run(ref, func(t *testing.T) {
			if _, err := ParseFunctionReference(ref); err == nil {
				t.Fatalf("ParseFunctionReference(%q) unexpectedly succeeded", ref)
			}
		})
	}
}
