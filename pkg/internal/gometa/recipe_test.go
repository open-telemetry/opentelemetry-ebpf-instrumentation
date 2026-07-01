// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recipeForMethod resolves a method by name on type t and returns its recipe.
func recipeForMethod(tb testing.TB, t *Type, methodName string, arch Arch) []ArgRecipe {
	tb.Helper()
	for _, m := range t.Methods() {
		if m.Name == methodName && m.FuncType != nil {
			r, err := BuildArgRecipe(m.FuncType, true, arch)
			require.NoError(tb, err)
			return r
		}
	}
	tb.Fatalf("method %q with funcType not found on %s", methodName, t.Name)
	return nil
}

// regAt returns the n-th Go regabi integer register offset for arch.
func regAt(arch Arch, n int) int {
	return regList(arch)[n]
}

func TestRecipe_PlaceStringInt_AMD64(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr)

	// Skip when the linker dropped Place's funcType this build.
	var place *Method
	for _, m := range ptr.Methods() {
		if m.Name == "Place" && m.FuncType != nil {
			mm := m
			place = &mm
			break
		}
	}
	if place == nil {
		t.Skip("Place.FuncType not retained in this build")
	}
	recipes, err := BuildArgRecipe(place.FuncType, true, ArchAMD64)
	require.NoError(t, err)

	// Layout for amd64 with receiver=*Order:
	//   AX (80) = receiver
	//   BX (40) = ctx.data (string ptr)
	//   CX (88) = ctx.len
	//   DI (112) = count
	require.Len(t, recipes, 2)

	assert.Equal(t, "arg0", recipes[0].Name)
	assert.Equal(t, EncGoString, recipes[0].Encoding)
	assert.Equal(t, regAt(ArchAMD64, 1), recipes[0].RegOff)
	assert.Equal(t, regAt(ArchAMD64, 2), recipes[0].LenReg)

	assert.Equal(t, "arg1", recipes[1].Name)
	assert.Equal(t, EncRegScalar, recipes[1].Encoding)
	assert.Equal(t, Int, recipes[1].Kind)
	assert.True(t, recipes[1].Signed)
	assert.Equal(t, regAt(ArchAMD64, 3), recipes[1].RegOff)
}

func TestRecipe_PlaceStringInt_ARM64(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr)
	var place *Method
	for _, m := range ptr.Methods() {
		if m.Name == "Place" && m.FuncType != nil {
			mm := m
			place = &mm
			break
		}
	}
	if place == nil {
		t.Skip("Place.FuncType not retained in this build")
	}
	recipes, err := BuildArgRecipe(place.FuncType, true, ArchARM64)
	require.NoError(t, err)
	require.Len(t, recipes, 2)

	assert.Equal(t, EncGoString, recipes[0].Encoding)
	assert.Equal(t, regAt(ArchARM64, 1), recipes[0].RegOff)
	assert.Equal(t, regAt(ArchARM64, 2), recipes[0].LenReg)
	assert.Equal(t, EncRegScalar, recipes[1].Encoding)
	assert.Equal(t, regAt(ArchARM64, 3), recipes[1].RegOff)
}

func TestRecipe_RefundString(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr)
	recipes := recipeForMethod(t, ptr, "Refund", ArchAMD64)
	require.Len(t, recipes, 1)
	assert.Equal(t, EncGoString, recipes[0].Encoding)
	assert.Equal(t, regAt(ArchAMD64, 1), recipes[0].RegOff,
		"receiver consumes slot 0, string.data lands on slot 1")
	assert.Equal(t, regAt(ArchAMD64, 2), recipes[0].LenReg)
}

// Synthesize a FuncType whose first arg is a pointer to main.Order so we can
// validate struct-field recipe generation without needing a real method.
func TestRecipe_PointerToStructFields(t *testing.T) {
	w := openFixture(t)
	ptr := w.TypeByName("*main.Order")
	require.NotNil(t, ptr)

	ft := &FuncType{In: []*Type{ptr}}
	recipes, err := BuildArgRecipe(ft, false, ArchAMD64)
	require.NoError(t, err)

	// main.Order = {Item(embedded struct), ID(uint64), Customer(string),
	// Amount(int32), Tags([]string)}.
	// We emit recipes only for primitive scalar + string fields:
	// ID, Customer, Amount. Item (struct) and Tags (slice) are skipped.
	byName := map[string]ArgRecipe{}
	for _, r := range recipes {
		byName[r.Name] = r
	}

	id, ok := byName["arg0.ID"]
	require.True(t, ok, "ID field recipe should be present")
	assert.Equal(t, EncPtrFieldScalar, id.Encoding)
	assert.Equal(t, Uint64, id.Kind)
	assert.Equal(t, uint64(16), id.FieldOff)
	assert.Equal(t, uint8(8), id.Size)
	assert.False(t, id.Signed)
	assert.Equal(t, regAt(ArchAMD64, 0), id.RegOff)

	customer, ok := byName["arg0.Customer"]
	require.True(t, ok)
	assert.Equal(t, EncPtrFieldGoString, customer.Encoding)
	assert.Equal(t, uint64(24), customer.FieldOff)
	assert.Equal(t, regAt(ArchAMD64, 0), customer.RegOff)

	amount, ok := byName["arg0.Amount"]
	require.True(t, ok)
	assert.Equal(t, EncPtrFieldScalar, amount.Encoding)
	assert.Equal(t, Int32, amount.Kind)
	assert.Equal(t, uint64(40), amount.FieldOff)
	assert.Equal(t, uint8(4), amount.Size)
	assert.True(t, amount.Signed)

	_, hasItem := byName["arg0.Item"]
	assert.False(t, hasItem, "embedded struct field is skipped (non-primitive)")
	_, hasTags := byName["arg0.Tags"]
	assert.False(t, hasTags, "slice field is skipped")
}

func TestRecipe_SliceAndInterfaceConsumeSlots(t *testing.T) {
	// A funcType: func(s []string, i any, n int) — no metadata reachable in
	// the fixture for this exact shape, so build the FuncType manually using
	// fixture-resolved Type entries.
	w := openFixture(t)
	tags := findFieldType(t, w, "main.Order", "Tags")
	require.Equal(t, Slice, tags.Kind)

	// Use any reachable interface type — package-level "*error" is created
	// in the fixture's funcType for Place.
	require.NotNil(t, w.TypeByName("*main.Order"))
	var ifaceT *Type
	for _, m := range w.TypeByName("*main.Order").Methods() {
		if m.FuncType == nil {
			continue
		}
		for _, o := range m.FuncType.Out {
			if o != nil && o.Kind == Interface {
				ifaceT = o
				break
			}
		}
		if ifaceT != nil {
			break
		}
	}
	if ifaceT == nil {
		t.Skip("no interface type reachable in fixture funcType")
	}

	intT := findFieldType(t, w, "main.Order", "ID")
	ft := &FuncType{In: []*Type{tags, ifaceT, intT}}

	recipes, err := BuildArgRecipe(ft, false, ArchAMD64)
	require.NoError(t, err)
	require.Len(t, recipes, 1, "only the final int arg yields a recipe")
	r := recipes[0]
	assert.Equal(t, "arg2", r.Name)
	// Slice consumed 3 regs, iface 2 regs → int lands on slot 5.
	assert.Equal(t, regAt(ArchAMD64, 5), r.RegOff)
}

func findFieldType(tb testing.TB, w *Walker, typeName, field string) *Type {
	tb.Helper()
	t := w.TypeByName(typeName)
	require.NotNil(tb, t)
	for _, f := range t.Fields() {
		if f.Name == field {
			require.NotNil(tb, f.Type)
			return f.Type
		}
	}
	tb.Fatalf("field %q not found on %s", field, typeName)
	return nil
}

func TestRecipe_TooManyArgs(t *testing.T) {
	w := openFixture(t)
	intT := findFieldType(t, w, "main.Order", "ID")

	// 10 int args + isMethod=true → 11 int slots. amd64 has 9. Should error.
	ft := &FuncType{In: make([]*Type, 10)}
	for i := range ft.In {
		ft.In[i] = intT
	}
	_, err := BuildArgRecipe(ft, true, ArchAMD64)
	assert.Error(t, err)
}

func TestEncoding_String(t *testing.T) {
	cases := []struct {
		e    Encoding
		want string
	}{
		{EncRegScalar, "reg-scalar"},
		{EncGoString, "reg-gostring"},
		{EncPtrFieldScalar, "ptr-field-scalar"},
		{EncPtrFieldGoString, "ptr-field-gostring"},
		{Encoding(0), "encoding?"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.e.String())
	}
}

func TestArch_String(t *testing.T) {
	assert.Equal(t, "amd64", ArchAMD64.String())
	assert.Equal(t, "arm64", ArchARM64.String())
	assert.Equal(t, "invalid", ArchInvalid.String())
}
