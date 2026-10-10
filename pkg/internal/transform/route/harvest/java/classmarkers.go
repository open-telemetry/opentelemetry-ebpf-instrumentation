// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"

import (
	"errors"
	"fmt"
)

// LanguageEvidence describes compiler markers on this class, not its dependencies.
type LanguageEvidence struct {
	Class    string
	Language string
	Markers  []string
}

const MaxClassBytes = 2 * 1024 * 1024

// InspectLanguage reuses the route parser's readers without collecting method annotations.
func InspectLanguage(data []byte) (LanguageEvidence, error) {
	var result LanguageEvidence
	if len(data) > MaxClassBytes {
		return result, errors.New("class size limit exceeded")
	}
	r := classReader{data: data}
	magic, err := r.u4()
	if err != nil || magic != classFileMagic {
		return result, errors.New("invalid class file magic")
	}
	if err := r.skip(4); err != nil {
		return result, err
	}
	cp, err := parseConstantPool(&r)
	if err != nil {
		return result, err
	}

	result.Class, err = readClassIdentity(&r, cp)
	if err != nil {
		return result, err
	}
	for range 2 { // Fields and methods have the same member_info layout.
		if err := skipMarkerMembers(&r, cp); err != nil {
			return result, err
		}
	}
	if err := readMarkerAttributes(&r, cp, &result); err != nil {
		return LanguageEvidence{}, err
	}
	if r.off != len(data) {
		return LanguageEvidence{}, errors.New("trailing class file data")
	}
	return result, nil
}

func readClassIdentity(r *classReader, cp constantPool) (string, error) {
	if err := r.skip(2); err != nil {
		return "", err
	}
	index, err := r.u2()
	if err != nil {
		return "", err
	}
	name, err := cp.className(index)
	if err != nil {
		return "", err
	}
	index, err = r.u2()
	if err != nil {
		return name, err
	}
	if index != 0 {
		if _, err := cp.className(index); err != nil {
			return name, err
		}
	}
	count, err := r.u2()
	if err != nil {
		return name, err
	}
	for range count {
		index, err := r.u2()
		if err != nil {
			return name, err
		}
		if _, err := cp.className(index); err != nil {
			return name, err
		}
	}
	return name, nil
}

func skipMarkerMembers(r *classReader, cp constantPool) error {
	count, err := r.u2()
	if err != nil {
		return err
	}
	for range count {
		if err := r.skip(2); err != nil {
			return err
		}
		for range 2 {
			index, err := r.u2()
			if err != nil {
				return err
			}
			if _, ok := cp.utf8(index); !ok {
				return errors.New("invalid member name or descriptor")
			}
		}
		if err := readMarkerAttributes(r, cp, nil); err != nil {
			return err
		}
	}
	return nil
}

func (cp constantPool) className(index uint16) (string, error) {
	if int(index) >= len(cp) || cp[index].tag != cpTagClass {
		return "", fmt.Errorf("invalid class index %d", index)
	}
	name, ok := cp.utf8(cp[index].index)
	if !ok {
		return "", errors.New("invalid class name reference")
	}
	return name, nil
}

func (e *LanguageEvidence) add(language, marker string) error {
	if e.Language != "" && e.Language != language {
		return errors.New("conflicting language markers")
	}
	e.Language = language
	e.Markers = append(e.Markers, marker)
	return nil
}

func readMarkerAttributes(r *classReader, cp constantPool, result *LanguageEvidence) error {
	count, err := r.u2()
	if err != nil {
		return err
	}
	for range count {
		index, err := r.u2()
		if err != nil {
			return err
		}
		name, ok := cp.utf8(index)
		if !ok {
			return errors.New("invalid attribute name reference")
		}
		length, err := r.u4()
		if err != nil {
			return err
		}
		data, err := r.bytes(int(length))
		if err != nil {
			return err
		}
		if result == nil {
			continue
		}
		if err := result.inspectAttribute(name, data, cp); err != nil {
			return err
		}
	}
	return nil
}

func (e *LanguageEvidence) inspectAttribute(name string, data []byte, cp constantPool) error {
	if name == "TASTY" {
		// Scala 3 stores a 128-bit TASTy UUID in the class attribute.
		if len(data) != 16 {
			return errors.New("invalid TASTY attribute length")
		}
		return e.add("scala", name)
	}
	if !isAnnotationsAttribute(name) {
		return nil
	}
	annotations, err := parseAnnotationsAttribute(data, cp)
	if err != nil {
		return err
	}
	for _, annotation := range annotations {
		var language string
		switch annotation.descriptor {
		case "Lkotlin/Metadata;":
			language = "kotlin"
		case "Lscala/reflect/ScalaSignature;", "Lscala/reflect/ScalaLongSignature;":
			language = "scala"
		default:
			continue
		}
		if err := e.add(language, annotation.descriptor); err != nil {
			return err
		}
	}
	return nil
}
