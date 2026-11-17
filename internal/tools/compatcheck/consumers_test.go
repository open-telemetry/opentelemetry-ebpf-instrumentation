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
			name:         "generic parameter rename with field removal",
			publicBefore: `package public; import "go.opentelemetry.io/obi/pkg/internal/options"; type Config struct { Options options.Options[int] }`,
			before:       "type Options[T any] struct { Value T }", after: "type Options[U any] struct {}",
			consumer: "_ = public.Config{}.Options.Value", want: "major",
		},
		{
			name: "narrowed generic constraint", publicBefore: "package public; func F[T ~int | ~string](v T) {}",
			publicAfter: "package public; func F[T ~int](v T) {}",
			consumer:    `public.F("value")`, want: "major",
		},
		{
			name: "narrowed named constraint", publicBefore: "package public; type Number interface { ~int | ~string }; func F[T Number](v T) {}",
			publicAfter: "package public; type Number interface { ~int }; func F[T Number](v T) {}",
			consumer:    `public.F("value")`, want: "major",
		},
		{
			name: "nested named constraint", publicBefore: "package public; type Inner interface { ~int | ~string }; type Number interface { Inner }; func F[T Number](v T) {}",
			publicAfter: "package public; type Inner interface { ~int }; type Number interface { Inner }; func F[T Number](v T) {}",
			consumer:    `public.F("value")`, want: "major",
		},
		{
			name: "relaxed generic constraint", publicBefore: "package public; func F[T ~int](v T) {}",
			publicAfter: "package public; func F[U ~int | ~string](v U) {}",
			consumer:    "public.F(1)", want: "minor",
		},
		{
			name: "generic parameter rename", publicBefore: "package public; func F[T any](v T) {}",
			publicAfter: "package public; func F[U any](v U) {}",
			consumer:    "public.F(1)", want: "patch",
		},
		{
			name: "array field length", publicBefore: "package public; type Event struct { Pad [11]byte }",
			publicAfter: "package public; type Event struct { Pad [9]byte }",
			consumer:    "var p [11]byte = public.Event{}.Pad; _ = p", want: "major",
		},
		{
			name: "comparability", publicBefore: "package public; type Snapshot struct { Value int }",
			publicAfter: "package public; type Snapshot struct { Value []int }",
			consumer:    "_ = public.Snapshot{} == public.Snapshot{}", want: "major",
		},
		{
			name: "constant value", publicBefore: "package public; const C = 3",
			publicAfter: "package public; const C = 4",
			consumer:    "var a [public.C-3]struct{}; var b [3-public.C]struct{}; _,_ = a,b", want: "major",
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
			findings, compareErr := compareAPI(before, after, "v1.0.0", "linux/amd64")
			if compareErr != nil {
				t.Fatal(compareErr)
			}
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

func TestAliasMoveConsumers(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserved", true: "field removed"}[broken], func(t *testing.T) {
			before := publicAPIFixture(t, `package public; type Config struct { Value int }; func F(Config) {}`, "")
			after := publicAPIFixture(t, `package public; import "go.opentelemetry.io/obi/pkg/metadata"; type Config = metadata.Config; func F(Config) {}`, "")
			writeFile(t, filepath.Join(before, "pkg/metadata/api.go"), "package metadata; const Existing = 1")
			body := "package metadata; const Existing = 1; type Config struct { Value int }"
			if broken {
				body = "package metadata; const Existing = 1; type Config struct {}"
			}
			writeFile(t, filepath.Join(after, "pkg/metadata/api.go"), body)
			oldAPI, err := loadAPI(t.Context(), before, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			newAPI, err := loadAPI(t.Context(), after, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			findings, err := compareAPI(oldAPI, newAPI, "v1.0.0", "linux/amd64")
			if err != nil {
				t.Fatal(err)
			}
			want := "minor"
			if broken {
				want = "major"
			}
			if got := minimumRelease(findings, "v1.0.0"); got != want {
				t.Fatalf("release=%s, want %s: %+v", got, want, findings)
			}
			consumer := `var c public.Config; c.Value = 1; public.F(c)`
			compileConsumer(t, before, consumer, true)
			compileConsumer(t, after, consumer, !broken)
		})
	}
}

func TestUnclassifiedPrivateStructIdentity(t *testing.T) {
	before := publicAPIFixture(t, `package public; type Event struct { Pid struct { _ int; ID int } }`, "")
	after := publicAPIFixture(t, `package public; type PID struct { _ int; ID int }; type Event struct { Pid PID }`, "")
	oldAPI, err := loadAPI(t.Context(), before, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	newAPI, err := loadAPI(t.Context(), after, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := compareAPI(oldAPI, newAPI, "v1.0.0", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Identifier == "Event.Pid" {
			found = f.Unsupported
		}
	}
	if !found {
		t.Fatalf("ambiguous nominal type change classified as proven break: %+v", findings)
	}
	compileConsumer(t, before, "var event public.Event; event.Pid.ID = 1", true)
	compileConsumer(t, after, "var event public.Event; event.Pid.ID = 1", true)
}
