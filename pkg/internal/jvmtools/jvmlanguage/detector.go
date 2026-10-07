// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmlanguage // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvmlanguage"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/jvmtools"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools/classfile"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxClassBytes   = classfile.MaxClassBytes
	maxArchiveBytes = 16 * 1024 * 1024
	maxTotalBytes   = 32 * 1024 * 1024
	maxRoots        = 32
)

// Result keeps uncertainty out of the exported language value.
type Result struct {
	Language   string   `json:"language,omitempty"`
	EntryClass string   `json:"entry_class,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// Detect is a research detector for a bounded subset of filesystem-based launches.
// Arguments exclude the java executable. An empty language means omit the attribute.
func Detect(root, cwd string, args []string, env map[string]string) (Result, error) {
	l, err := parseLaunch(args, env)
	if err != nil {
		return Result{}, err
	}
	if l.source {
		_, info, ok := langtools.StatProcessPath(root, cwd, l.main)
		if !ok || !info.Mode().IsRegular() {
			return Result{}, errors.New("unreadable source entry")
		}
		return Result{Language: "java", Evidence: []string{"java-source-launch"}}, nil
	}
	cp := jvmtools.ParseJavaLaunch(l.vmArgs, env)
	if strings.Contains(cp.Classpath, "*") {
		return Result{}, errors.New("wildcard classpaths are unsupported in this PoC")
	}
	if cp.Classpath == "" {
		cp.Classpath = cwd
	}
	entries := filepath.SplitList(cp.Classpath)
	if l.jar != "" {
		entries = []string{l.jar}
	}
	if len(entries) > maxRoots {
		return Result{}, errors.New("classpath root limit exceeded")
	}
	budget := maxTotalBytes
	for _, entry := range entries {
		if entry == "" {
			entry = cwd
		}
		path, info, ok := langtools.StatProcessPath(root, cwd, entry)
		if !ok {
			return Result{}, fmt.Errorf("unresolvable classpath root %q", entry)
		}
		var data []byte
		if info.IsDir() {
			if l.jar != "" {
				return Result{}, errors.New("jar path is a directory")
			}
			member, err := classMember(l.main)
			if err != nil {
				return Result{}, err
			}
			_, err = os.Lstat(filepath.Join(path, member))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return Result{}, err
			}
			classPath, ok := langtools.ResolveProcessPath(root, cwd, filepath.Join(entry, member))
			if !ok {
				return Result{}, fmt.Errorf("unsafe class path %q", l.main)
			}
			data, _, err = langtools.ReadMetadataFile(classPath, maxClassBytes)
			if err != nil || data == nil {
				return Result{}, fmt.Errorf("cannot read class %q safely", l.main)
			}
		} else {
			var err error
			data, l.main, err = readArchiveClass(path, l.main, l.jar != "", &budget)
			if err != nil {
				return Result{}, err
			}
			if data == nil {
				continue
			}
		}
		marker, err := classfile.InspectLanguage(data)
		if err != nil {
			return Result{}, err
		}
		if marker.Class != strings.ReplaceAll(l.main, ".", "/") {
			return Result{}, errors.New("class identity does not match entry point")
		}
		result := Result{Language: marker.Language, EntryClass: l.main, Evidence: marker.Markers}
		if result.Language == "" {
			result.Reason = "no recognized compiler marker; Java is not inferred"
		}
		return result, nil
	}
	return Result{}, errors.New("entry class not found")
}

func classMember(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\;[") {
		return "", errors.New("invalid entry class name")
	}
	if slices.Contains(strings.Split(name, "."), "") {
		return "", errors.New("invalid entry class name")
	}
	return strings.ReplaceAll(name, ".", "/") + ".class", nil
}
