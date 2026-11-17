// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPublicAPIConsumers(t *testing.T) {
	const publicConfig = `package public
import "go.opentelemetry.io/obi/pkg/internal/options"
type Config struct { Options options.Options }
`
	for _, tc := range []struct {
		name         string
		publicBefore string
		publicAfter  string
		before       string
		after        string
		consumer     string
		want         string
	}{
		{
			name: "package rename", publicBefore: "package public; func F() {}", publicAfter: "package renamed; func F() {}",
			consumer: "public.F()", want: "major",
		},
		{
			name: "internal field removed", publicBefore: publicConfig,
			before: "type Options struct { Value int }", after: "type Options struct {}",
			consumer: "_ = public.Config{}.Options.Value", want: "major",
		},
		{
			name: "internal field type", publicBefore: publicConfig,
			before: "type Options struct { Value int }", after: "type Options struct { Value string }",
			consumer: "var value int = public.Config{}.Options.Value; _ = value", want: "major",
		},
		{
			name:         "unexported internal type method",
			publicBefore: `package public; import "go.opentelemetry.io/obi/pkg/internal/options"; var Options = options.New()`,
			before:       "type hidden struct{}; func New() *hidden { return nil }; func (*hidden) Value() int { return 0 }",
			after:        "type hidden struct{}; func New() *hidden { return nil }",
			consumer:     "_ = public.Options.Value()", want: "major",
		},
		{
			name:         "internal generic instance",
			publicBefore: `package public; import "go.opentelemetry.io/obi/pkg/internal/options"; type Config struct { Options options.Options[int] }`,
			before:       "type Options[T any] struct { Value T }", after: "type Options[T any] struct { Value string }",
			consumer: "var value int = public.Config{}.Options.Value; _ = value", want: "major",
		},
		{
			name: "internal interface method", publicBefore: publicConfig,
			before: "type Options interface { A() }", after: "type Options interface { A(); B() }",
			consumer: "var c public.Config; var v interface { A() }; c.Options = v; _ = c", want: "major",
		},
		{
			name:         "internal generic method",
			publicBefore: `package public; import "go.opentelemetry.io/obi/pkg/internal/options"; type Config struct { Options options.Options[int] }`,
			before:       "type Options[T any] struct{}; func (*Options[T]) Value() T { var zero T; return zero }",
			after:        "type Options[T any] struct{}; func (*Options[T]) Value() string { return \"\" }",
			consumer:     "var c public.Config; var value int = c.Options.Value(); _ = value", want: "major",
		},
		{
			name:         "internal alias",
			publicBefore: `package public; import "go.opentelemetry.io/obi/pkg/internal/options"; type Config = options.Options`,
			before:       "type Options struct { Value int }", after: "type Options struct {}",
			consumer: "_ = public.Config{}.Value", want: "major",
		},
		{
			name: "recursive internal type", publicBefore: publicConfig,
			before: "type Options struct { Next *Options; Value int }", after: "type Options struct { Next *Options }",
			consumer: "_ = public.Config{}.Options.Next.Value", want: "major",
		},
		{
			name: "unrelated internal declaration", publicBefore: publicConfig,
			before: "type Options struct { Value int }; func Unrelated() {}", after: "type Options struct { Value int }",
			consumer: "_ = public.Config{}.Options.Value", want: "patch",
		},
		{
			name: "unreachable internal field", publicBefore: publicConfig,
			before:   "type Options struct { hidden Unrelated }; type Unrelated struct { Value int }",
			after:    "type Options struct { hidden Unrelated }; type Unrelated struct{}",
			consumer: "_ = public.Config{}", want: "patch",
		},
		{
			name: "internal field addition", publicBefore: publicConfig,
			before: "type Options struct { Value int }", after: "type Options struct { Value, Added int }",
			consumer: "_ = public.Config{}.Options.Value", want: "minor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.publicAfter == "" {
				tc.publicAfter = tc.publicBefore
			}
			beforeRoot := publicAPIFixture(t, tc.publicBefore, tc.before)
			afterRoot := publicAPIFixture(t, tc.publicAfter, tc.after)
			before, err := loadAPI(t.Context(), beforeRoot, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			after, err := loadAPI(t.Context(), afterRoot, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			findings := compareAPI(before, after, "v1.0.0", "linux/amd64")
			if got := minimumRelease(findings, "v1.0.0"); got != tc.want {
				t.Fatalf("minimum release=%s, want %s; findings=%+v", got, tc.want, findings)
			}
			compileConsumer(t, beforeRoot, tc.consumer, true)
			compileConsumer(t, afterRoot, tc.consumer, tc.want != "major")
		})
	}
}

func publicAPIFixture(t *testing.T, public, internal string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module "+coreModule+"\n\ngo 1.26.0\n")
	writeFile(t, filepath.Join(root, "pkg/public/api.go"), public)
	if internal != "" {
		writeFile(t, filepath.Join(root, "pkg/internal/options/api.go"), "package options; "+internal)
	}
	return root
}

func compileConsumer(t *testing.T, root, statement string, wantSuccess bool) {
	t.Helper()
	consumer := t.TempDir()
	writeFile(t, filepath.Join(consumer, "go.mod"), "module example.com/consumer\n\ngo 1.26.0\n\nrequire "+coreModule+" v1.0.0\nreplace "+coreModule+" => "+root+"\n")
	writeFile(t, filepath.Join(consumer, "main.go"), `package main; import "go.opentelemetry.io/obi/pkg/public"; func main() { `+statement+" }\n")
	cmd := exec.CommandContext(t.Context(), "go", "build", ".")
	cmd.Dir = consumer
	cmd.Env = goEnvironment("amd64")
	out, err := cmd.CombinedOutput()
	if (err == nil) != wantSuccess {
		t.Fatalf("consumer success=%t, want %t: %s", err == nil, wantSuccess, out)
	}
}
