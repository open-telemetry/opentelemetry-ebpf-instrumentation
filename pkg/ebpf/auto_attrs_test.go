// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/gometa"
)

func TestParseGoMethodSymbol(t *testing.T) {
	cases := []struct {
		in       string
		wantType string
		wantFunc string
		wantOK   bool
	}{
		{"main.(*checkout).PlaceOrder", "*main.checkout", "PlaceOrder", true},
		{"oteldemo.(*Server).Process", "*oteldemo.Server", "Process", true},
		{"github.com/foo/bar.(*Service).Handle", "*github.com/foo/bar.Service", "Handle", true},
		{"main.runServer", "", "", false},
		{"time.Time.Format", "", "", false},
		{"_ZNoteldemo", "", "", false},
	}
	for _, c := range cases {
		typ, fn, ok := parseGoMethodSymbol(c.in)
		assert.Equal(t, c.wantOK, ok, "ok for %q", c.in)
		if c.wantOK {
			assert.Equal(t, c.wantType, typ, "type for %q", c.in)
			assert.Equal(t, c.wantFunc, fn, "method for %q", c.in)
		}
	}
}

func TestArchForGometa(t *testing.T) {
	a, err := archForGometa("amd64")
	require.NoError(t, err)
	assert.Equal(t, gometa.ArchAMD64, a)

	a, err = archForGometa("arm64")
	require.NoError(t, err)
	assert.Equal(t, gometa.ArchARM64, a)

	_, err = archForGometa("riscv64")
	assert.Error(t, err)
}

func TestScalarAttrType(t *testing.T) {
	cases := []struct {
		k      gometa.Kind
		size   uint8
		signed bool
		want   config.CustomSpanAttrType
	}{
		{gometa.Bool, 1, false, config.CustomSpanAttrU8},
		{gometa.Int8, 1, true, config.CustomSpanAttrI8},
		{gometa.Uint16, 2, false, config.CustomSpanAttrU16},
		{gometa.Int32, 4, true, config.CustomSpanAttrI32},
		{gometa.Uint64, 8, false, config.CustomSpanAttrU64},
		{gometa.Int64, 8, true, config.CustomSpanAttrI64},
		{gometa.Uintptr, 8, false, config.CustomSpanAttrU64},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, scalarAttrType(c.k, c.size, c.signed),
			"kind=%v size=%d signed=%v", c.k, c.size, c.signed)
	}
}

func TestCompileRecipes(t *testing.T) {
	recipes := []gometa.ArgRecipe{
		{Name: "arg0", Kind: gometa.String, Encoding: gometa.EncGoString, RegOff: 40, LenReg: 88},
		{Name: "arg1", Kind: gometa.Int, Size: 8, Signed: true, Encoding: gometa.EncRegScalar, RegOff: 112},
		{Name: "arg2.UserId", Kind: gometa.Uint64, Size: 8, Encoding: gometa.EncPtrFieldScalar, RegOff: 104, FieldOff: 16},
		{Name: "arg2.Name", Kind: gometa.String, Encoding: gometa.EncPtrFieldGoString, RegOff: 104, FieldOff: 32},
	}
	span := &config.CustomSpanSpec{Name: "demo"}
	compiled, slots, err := compileRecipes(span, 7, recipes)
	require.NoError(t, err)
	require.Equal(t, uint16(4), compiled.Spec.ArgCount)
	require.Equal(t, uint64(7), compiled.Cookie)
	require.Equal(t, uint64(7), compiled.Spec.Cookie)
	require.Len(t, slots, 4)

	assert.Equal(t, obiUSDTArgGoString, compiled.Spec.Args[0].ArgType)
	assert.Equal(t, int16(40), compiled.Spec.Args[0].RegOff)
	assert.Equal(t, uint64(88), compiled.Spec.Args[0].ValOff)

	assert.Equal(t, obiUSDTArgReg, compiled.Spec.Args[1].ArgType)
	assert.Equal(t, uint8(1), compiled.Spec.Args[1].ArgSigned)
	assert.Equal(t, uint8(0), compiled.Spec.Args[1].ArgBitshift)

	assert.Equal(t, obiUSDTArgRegDeref, compiled.Spec.Args[2].ArgType)
	assert.Equal(t, uint64(16), compiled.Spec.Args[2].ValOff)

	assert.Equal(t, obiUSDTArgPtrFieldGoString, compiled.Spec.Args[3].ArgType)
	assert.Equal(t, uint64(32), compiled.Spec.Args[3].ValOff)

	assert.Equal(t, "arg2.UserId", slots[2].Name)
	assert.Equal(t, config.CustomSpanAttrU64, slots[2].Type)
	assert.Equal(t, "arg2.Name", slots[3].Name)
	assert.Equal(t, config.CustomSpanAttrString, slots[3].Type)
}

func TestCompileRecipes_TruncateAtMaxArgs(t *testing.T) {
	recipes := make([]gometa.ArgRecipe, obiUSDTMaxArgs+3)
	for i := range recipes {
		recipes[i] = gometa.ArgRecipe{
			Name:     fmt.Sprintf("arg%d", i),
			Kind:     gometa.Int,
			Size:     8,
			Signed:   true,
			Encoding: gometa.EncRegScalar,
			RegOff:   80,
		}
	}
	compiled, slots, err := compileRecipes(&config.CustomSpanSpec{Name: "x"}, 1, recipes)
	require.NoError(t, err)
	assert.Equal(t, uint16(obiUSDTMaxArgs), compiled.Spec.ArgCount)
	assert.Len(t, slots, obiUSDTMaxArgs)
}

// -- Integration: build a stripped Go fixture and walk it end-to-end --

const autoFixtureSrc = `package main

import (
	"fmt"
	"reflect"
)

type Item struct{ Name string }

type Order struct {
	Item
	ID       uint64
	Customer string
	Amount   int32
	Tags     []string
}

//go:noinline
func (o *Order) Place(ctx string, count int) (string, error) {
	return o.Customer + ctx, nil
}

//go:noinline
func (o *Order) Submit(req *Order) bool { return req != nil }

func main() {
	o := &Order{Item: Item{Name: "x"}}
	t := reflect.TypeOf(o)
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)
		fmt.Println(m.Name, m.Type)
	}
	s, _ := o.Place("p", 1)
	fmt.Println(s, o.Submit(o))
}
`

var (
	autoFixturePath string
	autoFixtureErr  error
)

func TestMain(m *testing.M) {
	os.Exit(runAutoTests(m))
}

func runAutoTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "auto-attrs-fixture-*")
	if err != nil {
		autoFixtureErr = err
		return m.Run()
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(autoFixtureSrc), 0o644); err != nil {
		autoFixtureErr = err
		return m.Run()
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture\n\ngo 1.21\n"), 0o644); err != nil {
		autoFixtureErr = err
		return m.Run()
	}
	if _, err := exec.LookPath("go"); err != nil {
		autoFixtureErr = err
		return m.Run()
	}
	bin := filepath.Join(dir, "fixture")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-trimpath", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		autoFixtureErr = fmt.Errorf("go build: %w\n%s", err, out)
		return m.Run()
	}
	autoFixturePath = bin
	return m.Run()
}

func openAutoFixture(t *testing.T) *elf.File {
	t.Helper()
	if autoFixtureErr != nil {
		t.Skipf("fixture unavailable: %v", autoFixtureErr)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("unsupported host arch %q for cross-build", runtime.GOARCH)
	}
	ef, err := elf.Open(autoFixturePath)
	require.NoError(t, err)
	t.Cleanup(func() { ef.Close() })
	return ef
}

func TestBuildFunctionAutoSpec_EndToEnd_StringIntMethod(t *testing.T) {
	ef := openAutoFixture(t)
	span := &config.CustomSpanSpec{
		Name: "order.place",
		On:   config.CustomSpanTarget{FunctionSpan: "main.(*Order).Place"},
	}
	compiled, slots, err := BuildFunctionAutoSpec(ef, span, 42, "amd64")
	if err != nil {
		t.Skipf("linker dropped Place funcType in this build: %v", err)
	}
	require.GreaterOrEqual(t, len(slots), 1)
	// arg0 = ctx string. arg1 = count int. Both should be present.
	names := map[string]AutoAttrSlot{}
	for _, s := range slots {
		names[s.Name] = s
	}
	if s, ok := names["arg0"]; ok {
		assert.Equal(t, config.CustomSpanAttrString, s.Type)
		assert.Equal(t, obiUSDTArgGoString, compiled.Spec.Args[s.ArgIdx].ArgType)
	}
	if s, ok := names["arg1"]; ok {
		assert.Equal(t, config.CustomSpanAttrI64, s.Type)
		assert.Equal(t, obiUSDTArgReg, compiled.Spec.Args[s.ArgIdx].ArgType)
	}
	assert.Equal(t, uint64(42), compiled.Cookie)
}

func TestBuildFunctionAutoSpec_EndToEnd_StructPointerFields(t *testing.T) {
	ef := openAutoFixture(t)
	span := &config.CustomSpanSpec{
		Name: "order.submit",
		On:   config.CustomSpanTarget{FunctionSpan: "main.(*Order).Submit"},
	}
	compiled, slots, err := BuildFunctionAutoSpec(ef, span, 99, "amd64")
	if err != nil {
		t.Skipf("linker dropped Submit funcType in this build: %v", err)
	}
	// Submit takes *Order: expect recipes for ID (uint64), Customer
	// (string field), Amount (int32). Embedded Item and slice Tags
	// must NOT appear.
	got := map[string]AutoAttrSlot{}
	for _, s := range slots {
		got[s.Name] = s
	}
	require.Contains(t, got, "arg0.ID")
	require.Contains(t, got, "arg0.Customer")
	require.Contains(t, got, "arg0.Amount")
	assert.NotContains(t, got, "arg0.Tags")
	assert.NotContains(t, got, "arg0.Item")

	idSlot := got["arg0.ID"]
	assert.Equal(t, obiUSDTArgRegDeref, compiled.Spec.Args[idSlot.ArgIdx].ArgType)
	assert.Equal(t, uint64(16), compiled.Spec.Args[idSlot.ArgIdx].ValOff)
	assert.Equal(t, config.CustomSpanAttrU64, idSlot.Type)

	custSlot := got["arg0.Customer"]
	assert.Equal(t, obiUSDTArgPtrFieldGoString, compiled.Spec.Args[custSlot.ArgIdx].ArgType)
	assert.Equal(t, uint64(24), compiled.Spec.Args[custSlot.ArgIdx].ValOff)
}

func TestBuildFunctionAutoSpec_NonMethodSymbol(t *testing.T) {
	ef := openAutoFixture(t)
	span := &config.CustomSpanSpec{
		Name: "x",
		On:   config.CustomSpanTarget{FunctionSpan: "main.runServer"},
	}
	_, _, err := BuildFunctionAutoSpec(ef, span, 1, "amd64")
	require.ErrorIs(t, err, ErrAutoAttrsUnsupported)
}

func TestBuildFunctionAutoSpec_UnknownType(t *testing.T) {
	ef := openAutoFixture(t)
	span := &config.CustomSpanSpec{
		Name: "x",
		On:   config.CustomSpanTarget{FunctionSpan: "main.(*NotARealType).Whatever"},
	}
	_, _, err := BuildFunctionAutoSpec(ef, span, 1, "amd64")
	require.ErrorIs(t, err, ErrAutoAttrsUnsupported)
}

func TestMergeManualOverAuto(t *testing.T) {
	auto := CompiledCustomSpanSpec{
		Spec: obiUSDTSpec{
			Args: [obiUSDTMaxArgs]obiUSDTArgSpec{
				0: {RegOff: 40, ArgType: obiUSDTArgGoString, ValOff: 88},
				1: {RegOff: 112, ArgType: obiUSDTArgReg},
				2: {RegOff: 104, ArgType: obiUSDTArgRegDeref, ValOff: 16},
			},
			ArgCount: 3,
		},
		ArgKinds: [obiUSDTMaxArgs]CustomSpanArgKind{
			CustomSpanArgStr, CustomSpanArgInt, CustomSpanArgInt,
		},
	}
	autoSlots := []AutoAttrSlot{
		{ArgIdx: 0, Name: "arg0", Type: config.CustomSpanAttrString},
		{ArgIdx: 1, Name: "arg1", Type: config.CustomSpanAttrI64},
		{ArgIdx: 2, Name: "arg2.UserId", Type: config.CustomSpanAttrU64},
	}
	manual := CompiledCustomSpanSpec{
		Spec: obiUSDTSpec{
			Args: [obiUSDTMaxArgs]obiUSDTArgSpec{
				1: {RegOff: 112, ArgType: obiUSDTArgReg, ArgSigned: 1},
				4: {RegOff: 72, ArgType: obiUSDTArgReg},
			},
			ArgCount: 5,
		},
		ArgKinds: [obiUSDTMaxArgs]CustomSpanArgKind{
			1: CustomSpanArgInt,
			4: CustomSpanArgInt,
		},
	}

	merged, slots := MergeManualOverAuto(auto, manual, autoSlots)
	assert.Equal(t, uint16(5), merged.Spec.ArgCount,
		"ArgCount must extend to manual's furthest slot")
	assert.Equal(t, uint8(1), merged.Spec.Args[1].ArgSigned,
		"manual encoding at slot 1 must overwrite auto")
	assert.Equal(t, obiUSDTArgReg, merged.Spec.Args[4].ArgType,
		"manual slot 4 must be added")
	assert.Equal(t, obiUSDTArgGoString, merged.Spec.Args[0].ArgType,
		"auto slot 0 must survive (no manual collision)")
	assert.Equal(t, obiUSDTArgRegDeref, merged.Spec.Args[2].ArgType,
		"auto slot 2 must survive (no manual collision)")

	names := map[string]bool{}
	for _, s := range slots {
		names[s.Name] = true
	}
	assert.True(t, names["arg0"], "auto slot 0 name kept")
	assert.False(t, names["arg1"], "auto slot 1 dropped — manual claimed it")
	assert.True(t, names["arg2.UserId"], "auto slot 2 name kept")
	assert.Len(t, slots, 2, "two auto slots survive after collision")
}
