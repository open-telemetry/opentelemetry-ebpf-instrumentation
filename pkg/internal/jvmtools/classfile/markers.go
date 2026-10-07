// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package classfile // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/classfile"

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
	if err := r.skip(2); err != nil {
		return result, err
	}
	index, err := r.u2()
	if err != nil {
		return result, err
	}
	result.Class, err = cp.className(index)
	if err != nil {
		return result, err
	}
	index, err = r.u2()
	if err != nil {
		return result, err
	}
	if index != 0 {
		if _, err := cp.className(index); err != nil {
			return result, err
		}
	}
	count, err := r.u2()
	if err != nil {
		return result, err
	}
	for range count {
		index, err := r.u2()
		if err != nil {
			return result, err
		}
		name, err := cp.className(index)
		if err != nil {
			return result, err
		}
		if name == "groovy/lang/GroovyObject" {
			if err := result.add("groovy", name); err != nil {
				return result, err
			}
		}
	}
	for range 2 { // Fields and methods have the same member_info layout.
		count, err := r.u2()
		if err != nil {
			return result, err
		}
		for range count {
			if err := r.skip(2); err != nil {
				return result, err
			}
			for range 2 {
				index, err := r.u2()
				if err != nil {
					return result, err
				}
				if _, ok := cp.utf8(index); !ok {
					return result, errors.New("invalid member name or descriptor")
				}
			}
			if err := readMarkerAttributes(&r, cp, nil); err != nil {
				return result, err
			}
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
		if name == "TASTY" {
			// Scala 3 stores a 128-bit TASTy UUID in the class attribute.
			if len(data) != 16 {
				return errors.New("invalid TASTY attribute length")
			}
			if err := result.add("scala", name); err != nil {
				return err
			}
		}
		if !isAnnotationsAttribute(name) {
			continue
		}
		annotations, err := parseAnnotationsAttribute(data, cp)
		if err != nil {
			return err
		}
		for _, annotation := range annotations {
			var language string
			switch annotation.Descriptor {
			case "Lkotlin/Metadata;":
				language = "kotlin"
			case "Lscala/reflect/ScalaSignature;", "Lscala/reflect/ScalaLongSignature;":
				language = "scala"
			}
			if language != "" {
				if err := result.add(language, annotation.Descriptor); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
