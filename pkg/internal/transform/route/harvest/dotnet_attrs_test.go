// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"strings"
	"testing"

	"github.com/microsoft/go-winmd/winmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotnetAttrs(t *testing.T) {
	_, md := openTestBlob(t)
	e := dotnetExtractor{ctx: context.Background(), md: md, rs: map[string]struct{}{}}

	require.NoError(t, e.attrs())

	assert.Equal(t, map[string]struct{}{
		"/api/Products": {},
		"/Get/{id}":     {},
		"/health":       {},
	}, e.rs)
}

func TestDotnetAttrsCancelled(t *testing.T) {
	_, md := openTestBlob(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := dotnetExtractor{ctx: ctx, md: md, rs: map[string]struct{}{}}

	assert.ErrorIs(t, e.attrs(), context.Canceled)
	assert.Empty(t, e.rs)
}

func TestDotnetAttrOwners(t *testing.T) {
	_, md := openTestBlob(t)
	e := dotnetExtractor{ctx: context.Background(), md: md}

	types, methods, err := e.attrOwners()
	require.NoError(t, err)

	products := dotnetType(t, md, "ProductsController")
	assert.Equal(t, dotnetOwner{ctrl: "Products"}, types[products])
	assert.Equal(t, dotnetOwner{ctrl: "Products", action: "Get"}, methods[dotnetMethod(t, md, products, "Get")])
	assert.Equal(t, dotnetOwner{ctrl: "Products", action: "Health"}, methods[dotnetMethod(t, md, products, "Health")])

	endpoints := dotnetType(t, md, "Endpoints")
	assert.Equal(t, dotnetOwner{ctrl: "Endpoints"}, types[endpoints])
}

func TestDotnetAttrOwnersCancelled(t *testing.T) {
	_, md := openTestBlob(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := dotnetExtractor{ctx: ctx, md: md}

	types, methods, err := e.attrOwners()

	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, types)
	assert.Nil(t, methods)
}

func TestDotnetAddAttr(t *testing.T) {
	_, md := openTestBlob(t)
	e := dotnetExtractor{ctx: context.Background(), md: md, rs: map[string]struct{}{}}
	types, methods, err := e.attrOwners()
	require.NoError(t, err)

	a := dotnetAttribute(t, &e, "HttpPostAttribute", "~/health")
	e.addAttr(a, types, methods)
	assert.Equal(t, map[string]struct{}{`/health`: {}}, e.rs)

	a.Parent.Tag = winmd.HasCustomAttribute_Assembly
	e.addAttr(a, types, methods)
	assert.Len(t, e.rs, 1)

	a.Type.Tag = winmd.CustomAttributeType_MethodDef
	e.addAttr(a, types, methods)
	assert.Len(t, e.rs, 1)
}

func TestDotnetAttrType(t *testing.T) {
	_, md := openTestBlob(t)
	e := dotnetExtractor{md: md}
	a := dotnetAttribute(t, &e, "RouteAttribute", "api/[controller]")

	name, ns, ok := e.attrType(a)
	assert.True(t, ok)
	assert.Equal(t, "RouteAttribute", name)
	assert.Equal(t, "Microsoft.AspNetCore.Mvc", ns)

	a.Type.Tag = winmd.CustomAttributeType_MethodDef
	_, _, ok = e.attrType(a)
	assert.False(t, ok)

	a.Type.Tag = winmd.CustomAttributeType_MemberRef
	a.Type.Index = winmd.Index(md.Tables.MemberRef.Len())
	_, _, ok = e.attrType(a)
	assert.False(t, ok)
}

func TestDotnetMemberType(t *testing.T) {
	_, md := openTestBlob(t)
	e := dotnetExtractor{md: md}
	a := dotnetAttribute(t, &e, "RouteAttribute", "api/[controller]")
	m, err := md.Tables.MemberRef.At(a.Type.Index)
	require.NoError(t, err)

	name, ns, ok := e.memberType(m)
	assert.True(t, ok)
	assert.Equal(t, "RouteAttribute", name)
	assert.Equal(t, "Microsoft.AspNetCore.Mvc", ns)

	m.Class.Tag = winmd.MemberRefParent_TypeDef
	m.Class.Index = dotnetType(t, md, "ProductsController")
	name, ns, ok = e.memberType(m)
	assert.True(t, ok)
	assert.Equal(t, "ProductsController", name)
	assert.Equal(t, "Routes", ns)

	m.Class.Tag = winmd.MemberRefParent_ModuleRef
	_, _, ok = e.memberType(m)
	assert.False(t, ok)

	m.Class.Tag = winmd.MemberRefParent_TypeRef
	m.Class.Index = winmd.Index(md.Tables.TypeRef.Len())
	_, _, ok = e.memberType(m)
	assert.False(t, ok)
}

func TestDotnetAttrString(t *testing.T) {
	tests := []struct {
		name string
		blob []byte
		want string
		ok   bool
	}{
		{name: "route", blob: []byte{1, 0, 4, '/', 'a', 'p', 'i', 0, 0}, want: "/api", ok: true},
		{name: "missing prolog", blob: []byte{4, '/', 'a', 'p', 'i'}},
		{name: "invalid prolog", blob: []byte{2, 0, 4, '/', 'a', 'p', 'i'}},
		{name: "null string", blob: []byte{1, 0, 0xff}},
		{name: "empty string", blob: []byte{1, 0, 0}},
		{name: "truncated string", blob: []byte{1, 0, 4, '/', 'a'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dotnetAttrString(tt.blob)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDotnetString(t *testing.T) {
	two := strings.Repeat("a", 128)
	four := strings.Repeat("b", 16384)
	tests := []struct {
		name string
		blob []byte
		want string
		ok   bool
	}{
		{name: "one-byte length", blob: append([]byte{4}, []byte("/api")...), want: "/api", ok: true},
		{name: "two-byte length", blob: append([]byte{0x80, 0x80}, []byte(two)...), want: two, ok: true},
		{name: "four-byte length", blob: append([]byte{0xc0, 0x00, 0x40, 0x00}, []byte(four)...), want: four, ok: true},
		{name: "ignores following data", blob: []byte{2, 'o', 'k', 9, 9}, want: "ok", ok: true},
		{name: "missing", blob: nil},
		{name: "null", blob: []byte{0xff}},
		{name: "empty", blob: []byte{0}},
		{name: "truncated length", blob: []byte{0x80}},
		{name: "truncated data", blob: []byte{4, '/', 'a'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dotnetString(tt.blob)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDotnetTokens(t *testing.T) {
	tests := []struct {
		name  string
		route string
		owner dotnetOwner
		want  string
	}{
		{
			name:  "controller and action",
			route: "api/[controller]/[action]/{id}",
			owner: dotnetOwner{ctrl: "Products", action: "Get"},
			want:  "api/Products/Get/{id}",
		},
		{
			name:  "case insensitive",
			route: "[CONTROLLER]/[AcTiOn]",
			owner: dotnetOwner{ctrl: "Products", action: "Get"},
			want:  "Products/Get",
		},
		{
			name:  "repeated token",
			route: "[controller]/[controller]",
			owner: dotnetOwner{ctrl: "Products"},
			want:  "Products/Products",
		},
		{
			name:  "unknown token",
			route: "[area]/[controller]",
			owner: dotnetOwner{ctrl: "Products"},
			want:  "[area]/Products",
		},
		{
			name:  "missing owner value",
			route: "[controller]/[action]",
			owner: dotnetOwner{ctrl: "Products"},
			want:  "Products/[action]",
		},
		{name: "unclosed token", route: "api/[controller", owner: dotnetOwner{ctrl: "Products"}, want: "api/[controller"},
		{name: "route parameter", route: "api/{id}", owner: dotnetOwner{ctrl: "Products"}, want: "api/{id}"},
		{name: "plain route", route: "api/health", owner: dotnetOwner{ctrl: "Products"}, want: "api/health"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dotnetTokens(tt.route, tt.owner))
		})
	}
}

func dotnetType(t *testing.T, md *winmd.Metadata, name string) winmd.Index {
	t.Helper()
	for i := range md.Tables.TypeDef.Indices() {
		typeDef, err := md.Tables.TypeDef.At(i)
		require.NoError(t, err)
		if typeDef.Name.String() == name {
			return i
		}
	}
	t.Fatalf("type %q not found", name)
	return 0
}

func dotnetMethod(t *testing.T, md *winmd.Metadata, owner winmd.Index, name string) winmd.Index {
	t.Helper()
	typeDef, err := md.Tables.TypeDef.At(owner)
	require.NoError(t, err)
	for i := range typeDef.MethodList.All() {
		method, err := md.Tables.MethodDef.At(i)
		require.NoError(t, err)
		if method.Name.String() == name {
			return i
		}
	}
	t.Fatalf("method %q not found", name)
	return 0
}

func dotnetAttribute(t *testing.T, e *dotnetExtractor, name, route string) winmd.CustomAttribute {
	t.Helper()
	for i := range e.md.Tables.CustomAttribute.Indices() {
		a, err := e.md.Tables.CustomAttribute.At(i)
		require.NoError(t, err)
		attrName, _, ok := e.attrType(a)
		if !ok || attrName != name {
			continue
		}
		r, ok := dotnetAttrString(a.Value)
		if ok && r == route {
			return a
		}
	}
	t.Fatalf("attribute %s(%q) not found", name, route)
	return winmd.CustomAttribute{}
}
