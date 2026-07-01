// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/gometa"
)

// AutoAttrSlot binds one BPF event slot to its span attribute name and type.
type AutoAttrSlot struct {
	ArgIdx uint8
	Name   string
	Type   config.CustomSpanAttrType
}

// ErrAutoAttrsUnsupported wraps every BuildFunctionAutoSpec failure path.
var ErrAutoAttrsUnsupported = errors.New("custom_span: auto_attrs target not supported")

// MergeManualOverAuto overlays manual attrs on top of auto: manual wins on
// arg-index collision; ArgCount extends to the union.
func MergeManualOverAuto(auto, manual CompiledCustomSpanSpec, autoSlots []AutoAttrSlot) (CompiledCustomSpanSpec, []AutoAttrSlot) {
	merged := auto
	claimed := make(map[uint8]struct{}, obiUSDTMaxArgs)
	for i := 0; i < obiUSDTMaxArgs; i++ {
		if manual.Spec.Args[i].ArgType != 0 {
			merged.Spec.Args[i] = manual.Spec.Args[i]
			merged.ArgKinds[i] = manual.ArgKinds[i]
			claimed[uint8(i)] = struct{}{}
		}
	}
	if manual.Spec.ArgCount > merged.Spec.ArgCount {
		merged.Spec.ArgCount = manual.Spec.ArgCount
	}
	survivors := autoSlots[:0]
	for _, s := range autoSlots {
		if _, taken := claimed[s.ArgIdx]; taken {
			continue
		}
		survivors = append(survivors, s)
	}
	return merged, survivors
}

// BuildFunctionAutoSpec walks ef's runtime type metadata and emits a spec
// for every primitive arg (and every primitive field of struct-ptr args).
// Wraps ErrAutoAttrsUnsupported on failure — caller falls back to manual.
func BuildFunctionAutoSpec(ef *elf.File, span *config.CustomSpanSpec, cookie uint64, arch string) (CompiledCustomSpanSpec, []AutoAttrSlot, error) {
	a, err := archForGometa(arch)
	if err != nil {
		return CompiledCustomSpanSpec{}, nil, err
	}
	recvName, methodName, ok := parseGoMethodSymbol(span.FunctionSymbol())
	if !ok {
		return CompiledCustomSpanSpec{}, nil, fmt.Errorf("%w: symbol %q is not a recognized Go method form (pkg.(*T).Method)",
			ErrAutoAttrsUnsupported, span.FunctionSymbol())
	}
	w, err := gometa.Open(ef)
	if err != nil {
		return CompiledCustomSpanSpec{}, nil, fmt.Errorf("%w: gometa open: %w", ErrAutoAttrsUnsupported, err)
	}
	recvT := w.TypeByName(recvName)
	if recvT == nil {
		return CompiledCustomSpanSpec{}, nil, fmt.Errorf("%w: receiver type %q not in .typelink",
			ErrAutoAttrsUnsupported, recvName)
	}
	var ft *gometa.FuncType
	for _, m := range recvT.Methods() {
		if m.Name == methodName && m.FuncType != nil {
			ft = m.FuncType
			break
		}
	}
	if ft == nil {
		return CompiledCustomSpanSpec{}, nil, fmt.Errorf("%w: method %s.%s funcType not retained by linker",
			ErrAutoAttrsUnsupported, recvName, methodName)
	}
	recipes, err := gometa.BuildArgRecipe(ft, true, a)
	if err != nil {
		return CompiledCustomSpanSpec{}, nil, fmt.Errorf("%w: %w", ErrAutoAttrsUnsupported, err)
	}
	return compileRecipes(span, cookie, recipes)
}

// compileRecipes turns gometa recipes into BPF spec entries + slot table.
func compileRecipes(_ *config.CustomSpanSpec, cookie uint64, recipes []gometa.ArgRecipe) (CompiledCustomSpanSpec, []AutoAttrSlot, error) {
	if len(recipes) > obiUSDTMaxArgs {
		recipes = recipes[:obiUSDTMaxArgs]
	}
	out := CompiledCustomSpanSpec{Cookie: cookie}
	out.Spec.Cookie = cookie
	slots := make([]AutoAttrSlot, 0, len(recipes))
	for i, r := range recipes {
		idx := uint8(i)
		spec, kind, attrType, ok := recipeToSpec(r)
		if !ok {
			continue
		}
		out.Spec.Args[idx] = spec
		out.ArgKinds[idx] = kind
		slots = append(slots, AutoAttrSlot{ArgIdx: idx, Name: r.Name, Type: attrType})
	}
	out.Spec.ArgCount = uint16(len(slots))
	return out, slots, nil
}

func recipeToSpec(r gometa.ArgRecipe) (obiUSDTArgSpec, CustomSpanArgKind, config.CustomSpanAttrType, bool) {
	spec := obiUSDTArgSpec{RegOff: int16(r.RegOff)}
	switch r.Encoding {
	case gometa.EncRegScalar:
		spec.ArgType = obiUSDTArgReg
		spec.ArgBitshift = sizeToBitshift(r.Size)
		spec.ArgSigned = boolToU8(r.Signed)
		return spec, CustomSpanArgInt, scalarAttrType(r.Kind, r.Size, r.Signed), true

	case gometa.EncGoString:
		spec.ArgType = obiUSDTArgGoString
		spec.ValOff = uint64(uint16(r.LenReg))
		return spec, CustomSpanArgStr, config.CustomSpanAttrString, true

	case gometa.EncPtrFieldScalar:
		spec.ArgType = obiUSDTArgRegDeref
		spec.ValOff = r.FieldOff
		spec.ArgBitshift = sizeToBitshift(r.Size)
		spec.ArgSigned = boolToU8(r.Signed)
		return spec, CustomSpanArgInt, scalarAttrType(r.Kind, r.Size, r.Signed), true

	case gometa.EncPtrFieldGoString:
		spec.ArgType = obiUSDTArgPtrFieldGoString
		spec.ValOff = r.FieldOff
		return spec, CustomSpanArgStr, config.CustomSpanAttrString, true
	}
	return obiUSDTArgSpec{}, CustomSpanArgNone, "", false
}

func scalarAttrType(k gometa.Kind, size uint8, signed bool) config.CustomSpanAttrType {
	if k == gometa.Bool {
		return config.CustomSpanAttrU8
	}
	switch size {
	case 1:
		if signed {
			return config.CustomSpanAttrI8
		}
		return config.CustomSpanAttrU8
	case 2:
		if signed {
			return config.CustomSpanAttrI16
		}
		return config.CustomSpanAttrU16
	case 4:
		if signed {
			return config.CustomSpanAttrI32
		}
		return config.CustomSpanAttrU32
	}
	if signed {
		return config.CustomSpanAttrI64
	}
	return config.CustomSpanAttrU64
}

func archForGometa(arch string) (gometa.Arch, error) {
	switch arch {
	case "amd64":
		return gometa.ArchAMD64, nil
	case "arm64":
		return gometa.ArchARM64, nil
	}
	return gometa.ArchInvalid, fmt.Errorf("gometa: unsupported arch %q", arch)
}

// parseGoMethodSymbol decodes "<pkg>.(*<Type>).<Method>" (ptr-receiver form
// only; value receivers and plain functions have no linker-retained funcType).
func parseGoMethodSymbol(symbol string) (typeName, method string, ok bool) {
	m := goPtrMethodRE.FindStringSubmatch(symbol)
	if m == nil {
		return "", "", false
	}
	return "*" + m[1] + "." + m[2], m[3], true
}

var goPtrMethodRE = regexp.MustCompile(`^([A-Za-z_][\w./-]*?)\.\(\*([A-Za-z_]\w*)\)\.([A-Za-z_]\w*)$`)
