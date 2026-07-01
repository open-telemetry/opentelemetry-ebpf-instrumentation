// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa

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
)

// fixtureSrc is the program we build and walk. It exercises:
//   - a value struct with mixed-type fields and one embedded field
//   - a pointer receiver with exported and unexported methods
//   - reflect references that force the linker to retain type metadata
const fixtureSrc = `package main

import (
	"fmt"
	"reflect"
)

type Item struct {
	Name string
}

type Order struct {
	Item              // embedded
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
func (o *Order) Refund(reason string) bool {
	return reason != ""
}

//go:noinline
func (o *Order) cancel(reason string) bool {
	return reason != ""
}

func main() {
	o := &Order{Item: Item{Name: "x"}}
	t := reflect.TypeOf(o)
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)
		fmt.Println(m.Name, m.Type)
	}
	s, _ := o.Place("p", 1)
	fmt.Println(s, o.Refund("r"), o.cancel("c"))
}
`

var (
	fixturePath string
	fixtureErr  error
)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "gometa-fixture-*")
	if err != nil {
		fixtureErr = err
		return m.Run()
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(fixtureSrc), 0o644); err != nil {
		fixtureErr = err
		return m.Run()
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture\n\ngo 1.21\n"), 0o644); err != nil {
		fixtureErr = err
		return m.Run()
	}
	if _, err := exec.LookPath("go"); err != nil {
		fixtureErr = err
		return m.Run()
	}
	bin := filepath.Join(dir, "fixture")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-trimpath", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		fixtureErr = fmt.Errorf("go build: %w\n%s", err, out)
		return m.Run()
	}
	fixturePath = bin
	return m.Run()
}

func openFixture(tb testing.TB) *Walker {
	tb.Helper()
	if fixtureErr != nil {
		tb.Skipf("fixture unavailable: %v", fixtureErr)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		tb.Skipf("unsupported host arch %q for cross-build", runtime.GOARCH)
	}
	ef, err := elf.Open(fixturePath)
	require.NoError(tb, err)
	tb.Cleanup(func() { ef.Close() })
	w, err := Open(ef)
	require.NoError(tb, err)
	return w
}

func TestOpen_FindsTypesBase(t *testing.T) {
	w := openFixture(t)
	assert.NotZero(t, w.typesBase, "types base should be resolved")
	assert.NotZero(t, w.textBase, "text base should be auto-detected from .text")
	assert.NotEmpty(t, w.typelinks, "typelinks must be parsed")
	assert.Equal(t, w.typesBase, w.rdataAddr,
		"on a typical 1.21+ binary types_base equals .rodata.Addr")
}

func TestTypeByName_LocatesPointerAndValue(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr, "*main.Order")
	assert.Equal(t, Pointer, ptr.Kind)
	assert.Equal(t, uint64(8), ptr.Size)

	val := w.TypeByName("main.Order")
	require.NotNil(t, val, "main.Order")
	assert.Equal(t, Struct, val.Kind)
	assert.NotZero(t, val.Size)
}

func TestMethods_OnPointerType(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr)
	methods := ptr.Methods()
	byName := make(map[string]Method, len(methods))
	for _, m := range methods {
		byName[m.Name] = m
	}
	require.Contains(t, byName, "Place")
	require.Contains(t, byName, "Refund")
	require.Contains(t, byName, "cancel")

	// EntryPC is best-effort: the linker may set tfn=-1 when a method body
	// is never called, even if its name remains in the method table for
	// reflection. Require that at least one method resolved.
	resolved := 0
	for _, m := range methods {
		if m.EntryPC != 0 {
			resolved++
		}
	}
	assert.Positive(t, resolved, "at least one method's EntryPC should resolve")
}

func TestFuncType_RetainedMethodDecodes(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr)

	// At least one of {Place,Refund} should have its funcType retained —
	// reflect.Method(i).Type in the fixture forces this. Verify the
	// signature when retained: receiver is NOT included in funcType.
	var sig *Method
	for _, m := range ptr.Methods() {
		if (m.Name == "Place" || m.Name == "Refund") && m.FuncType != nil {
			sig = &m
			break
		}
	}
	require.NotNil(t, sig, "linker should retain funcType for at least one reflected method")

	switch sig.Name {
	case "Place":
		require.Len(t, sig.FuncType.In, 2)
		assert.Equal(t, String, sig.FuncType.In[0].Kind)
		assert.Equal(t, Int, sig.FuncType.In[1].Kind)
		require.Len(t, sig.FuncType.Out, 2)
		assert.Equal(t, String, sig.FuncType.Out[0].Kind)
		assert.Equal(t, Interface, sig.FuncType.Out[1].Kind)
	case "Refund":
		require.Len(t, sig.FuncType.In, 1)
		assert.Equal(t, String, sig.FuncType.In[0].Kind)
		require.Len(t, sig.FuncType.Out, 1)
		assert.Equal(t, Bool, sig.FuncType.Out[0].Kind)
	}
}

func TestFields_OrderAndOffsets(t *testing.T) {
	w := openFixture(t)
	val := w.TypeByName("main.Order")
	require.NotNil(t, val)
	fields := val.Fields()
	require.Len(t, fields, 5)

	assert.Equal(t, "Item", fields[0].Name)
	assert.True(t, fields[0].Embedded)
	assert.Equal(t, uint64(0), fields[0].Offset)

	assert.Equal(t, "ID", fields[1].Name)
	require.NotNil(t, fields[1].Type)
	assert.Equal(t, Uint64, fields[1].Type.Kind)

	assert.Equal(t, "Customer", fields[2].Name)
	require.NotNil(t, fields[2].Type)
	assert.Equal(t, String, fields[2].Type.Kind)

	assert.Equal(t, "Amount", fields[3].Name)
	require.NotNil(t, fields[3].Type)
	assert.Equal(t, Int32, fields[3].Type.Kind)

	assert.Equal(t, "Tags", fields[4].Name)
	require.NotNil(t, fields[4].Type)
	assert.Equal(t, Slice, fields[4].Type.Kind)

	// Offsets must be monotonically increasing and within Size.
	prev := uint64(0)
	for i, f := range fields {
		if i > 0 {
			assert.Greater(t, f.Offset, prev, "field %s offset", f.Name)
		}
		prev = f.Offset
	}
	assert.Less(t, prev, val.Size)
}

func TestElem_FollowsPointer(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr)
	elem := ptr.Elem()
	require.NotNil(t, elem)
	assert.Equal(t, "main.Order", elem.Name)
	assert.Equal(t, Struct, elem.Kind)
}

func TestSlice_FieldElemIsConcreteType(t *testing.T) {
	w := openFixture(t)
	val := w.TypeByName("main.Order")
	require.NotNil(t, val)
	var tags Field
	for _, f := range val.Fields() {
		if f.Name == "Tags" {
			tags = f
			break
		}
	}
	require.NotNil(t, tags.Type)
	require.Equal(t, Slice, tags.Type.Kind)
	elem := tags.Type.Elem()
	require.NotNil(t, elem)
	assert.Equal(t, String, elem.Kind)
}

func TestTypes_IterTerminatesEarly(t *testing.T) {
	w := openFixture(t)
	count := 0
	w.Types(func(_ *Type) bool {
		count++
		return count < 5
	})
	assert.Equal(t, 5, count, "iterator must stop when yield returns false")
}

func TestTypes_ClosureReachesNonTypelinkType(t *testing.T) {
	w := openFixture(t)
	// main.Order is reached transitively from *main.Order via Elem.
	require.NotNil(t, w.TypeByName("*main.Order"))
	require.NotNil(t, w.TypeByName("main.Order"))
}

func TestOpen_NoTypelinks(t *testing.T) {
	// Open an ELF that has no .typelink (e.g. a non-Go binary). Pick the
	// fixture and zero out the section to simulate it cheaply: we can't
	// modify *elf.File so we exercise the error path by feeding a
	// hand-crafted file at the failing point.
	if runtime.GOOS != "linux" {
		t.Skip("only meaningful where /bin/ls exists as a non-Go ELF")
	}
	ef, err := elf.Open("/bin/ls")
	if err != nil {
		t.Skipf("no system ELF available: %v", err)
	}
	defer ef.Close()
	_, err = Open(ef)
	assert.ErrorIs(t, err, ErrNoTypelinks)
}
