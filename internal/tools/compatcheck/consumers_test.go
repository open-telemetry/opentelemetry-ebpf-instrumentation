// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"strings"
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
			name:         "private type rename",
			publicBefore: `package public;import "go.opentelemetry.io/obi/pkg/internal/options";var Options=options.New()`,
			before:       "type hidden struct{Value int};func New()*hidden{return nil}",
			after:        "type renamed struct{Value int};func New()*renamed{return nil}",
			consumer:     "_=public.Options.Value",
			want:         "patch",
		},
		{
			name:         "recursive constraint parameter rename",
			publicBefore: "package public;type Self struct{};func(Self) M(Self){};func F[T interface{M(T)}](v T){}",
			publicAfter:  "package public;type Self struct{};func(Self) M(Self){};func F[U interface{M(U)}](v U){}",
			consumer:     "public.F(public.Self{})",
			want:         "patch",
		},
		{
			name:         "concrete method addition",
			publicBefore: "package public;type T struct{};func(T) Existing(){}",
			publicAfter:  "package public;type T struct{};func(T) Existing(){};func(T) Added(){}",
			consumer:     "public.T{}.Existing()",
			want:         "minor",
		},
		{
			name:         "removed exported function",
			publicBefore: "package public;func F(){}",
			publicAfter:  "package public",
			consumer:     "public.F()",
			want:         "major",
		},
		{
			name:         "removed exported type",
			publicBefore: "package public;type T struct{}",
			publicAfter:  "package public",
			consumer:     "var value public.T;_=value",
			want:         "major",
		},
		{
			name:         "removed exported constant",
			publicBefore: "package public;const C=1",
			publicAfter:  "package public",
			consumer:     "_=public.C",
			want:         "major",
		},
		{
			name:         "removed concrete method",
			publicBefore: "package public;type T struct{};func(T) M(){}",
			publicAfter:  "package public;type T struct{}",
			consumer:     "public.T{}.M()",
			want:         "major",
		},
		{
			name:         "function parameter type",
			publicBefore: "package public;func F(int){}",
			publicAfter:  "package public;func F(string){}",
			consumer:     "public.F(1)",
			want:         "major",
		},
		{
			name:         "function result type",
			publicBefore: "package public;func F()int{return 0}",
			publicAfter:  `package public;func F()string{return ""}`,
			consumer:     "var value int=public.F();_=value",
			want:         "major",
		},
		{
			name:         "variadic signature",
			publicBefore: "package public;func F(int){}",
			publicAfter:  "package public;func F(...int){}",
			consumer:     "var f func(int)=public.F;_=f",
			want:         "major",
		},
		{
			name:         "exported interface method addition",
			publicBefore: "package public;type I interface{A()}",
			publicAfter:  "package public;type I interface{A();B()}",
			consumer:     "var target public.I;var old interface{A()};target=old;_=target",
			want:         "major",
		},
		{
			name:         "ABI-only private layout",
			publicBefore: "package public;type T struct{Value int;hidden [1]byte}",
			publicAfter:  "package public;type T struct{hidden [64]byte;Value int}",
			consumer:     "_=public.T{Value:1}.Value",
			want:         "patch",
		},
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
			changes, compareErr := compareAPI(before, after, "v1.0.0", "linux/amd64")
			if compareErr != nil {
				t.Fatal(compareErr)
			}
			if got := minimumRelease(changes, "v1.0.0"); got != tc.want {
				t.Fatalf("minimum release=%s, want %s; changes=%+v", got, tc.want, changes)
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

func compileConsumer(t *testing.T, root, statement string, wantSuccess bool, replacements ...string) {
	t.Helper()
	consumer := t.TempDir()
	writeFile(t, filepath.Join(consumer, "go.mod"), "module example.com/consumer\n\ngo 1.26.0\n\nrequire "+coreModule+" v1.0.0\nreplace "+coreModule+" => "+root+"\n"+strings.Join(replacements, "\n"))
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
			changes, err := compareAPI(oldAPI, newAPI, "v1.0.0", "linux/amd64")
			if err != nil {
				t.Fatal(err)
			}
			want := "minor"
			if broken {
				want = "major"
			}
			if got := minimumRelease(changes, "v1.0.0"); got != want {
				t.Fatalf("release=%s, want %s: %+v", got, want, changes)
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
	changes, err := compareAPI(oldAPI, newAPI, "v1.0.0", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range changes {
		if f.Identifier == "Event.Pid" {
			found = f.Unsupported
		}
	}
	if !found {
		t.Fatalf("ambiguous nominal type change classified as proven break: %+v", changes)
	}
	compileConsumer(t, before, "var event public.Event; event.Pid.ID = 1", true)
	compileConsumer(t, after, "var event public.Event; event.Pid.ID = 1", true)
}

func TestDependencyUpdateClassification(t *testing.T) {
	for _, dependency := range []string{"example.com/dependency", coreModule + "/collector"} {
		for _, breaking := range []bool{false, true} {
			t.Run(dependency+"/"+map[bool]string{false: "compatible addition", true: "exposed field break"}[breaking], func(t *testing.T) {
				var roots []string
				var apis []*apiSnapshot
				for _, candidate := range []bool{false, true} {
					root := publicAPIFixture(t, `package public;import "`+dependency+`";var Value dependency.Value`, "")
					writeFile(t, filepath.Join(root, "go.mod"), "module "+coreModule+"\n\ngo 1.26.0\nrequire "+dependency+" v0.1.0\nreplace "+dependency+" => ./dependency\n")
					writeFile(t, filepath.Join(root, "dependency/go.mod"), "module "+dependency+"\n\ngo 1.26.0\n")
					body := "package dependency;type Value struct{Existing int}"
					if candidate {
						body = "package dependency;type Value struct{Existing int;Added int}"
						if breaking {
							body = "package dependency;type Value struct{Existing string}"
						}
					}
					writeFile(t, filepath.Join(root, "dependency/value.go"), body)
					api, err := loadAPI(t.Context(), root, "amd64")
					if err != nil {
						t.Fatal(err)
					}
					roots = append(roots, root)
					apis = append(apis, api)
				}
				changes, err := compareAPI(apis[0], apis[1], "v1.0.0", "linux/amd64")
				if err != nil {
					t.Fatal(err)
				}
				want := "patch"
				if breaking {
					want = "major"
				}
				if got := minimumRelease(changes, "v1.0.0"); got != want {
					t.Fatalf("release=%s, want %s: %+v", got, want, changes)
				}
				findings, unknown := actionableChanges(changes)
				if len(unknown) != 0 || (len(findings) > 0) != breaking {
					t.Fatalf("unexpected classification: %+v %+v", findings, unknown)
				}
				for i, root := range roots {
					compileConsumer(t, root, "var value int=public.Value.Existing;_=value", i == 0 || !breaking, "require "+dependency+" v0.1.0\nreplace "+dependency+" => "+filepath.Join(root, "dependency"))
				}
			})
		}
	}
}

func TestAliasReplacedByDefinedType(t *testing.T) {
	before := publicAPIFixture(t, `package public;import "go.opentelemetry.io/obi/pkg/metadata";type Config = metadata.Config;func Consume(metadata.Config){}`, "")
	after := publicAPIFixture(t, `package public;import "go.opentelemetry.io/obi/pkg/metadata";type Config metadata.Config;func Consume(metadata.Config){}`, "")
	var snapshots []*apiSnapshot
	for _, root := range []string{before, after} {
		writeFile(t, filepath.Join(root, "pkg/metadata/api.go"), "package metadata;type Config struct{Value int}")
		api, err := loadAPI(t.Context(), root, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, api)
	}
	changes, err := compareAPI(snapshots[0], snapshots[1], "v1.0.0", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if minimumRelease(changes, "v1.0.0") != "major" {
		t.Fatalf("alias identity break missed: %+v", changes)
	}
	compileConsumer(t, before, "public.Consume(public.Config{})", true)
	compileConsumer(t, after, "public.Consume(public.Config{})", false)
}
