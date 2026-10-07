// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmlanguage // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvmlanguage"

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const maxArchiveEntries = 4096

func readArchiveClass(path, main string, executable bool, budget *int) ([]byte, string, error) {
	limit := min(maxArchiveBytes, *budget)
	data, _, err := langtools.ReadMetadataFile(path, int64(limit))
	if err != nil || data == nil {
		return nil, main, fmt.Errorf("unreadable or oversized archive %q", path)
	}
	*budget -= len(data)
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, main, err
	}
	if len(z.File) > maxArchiveEntries {
		return nil, main, errors.New("archive entry limit exceeded")
	}
	manifestData, err := readMember(z, "META-INF/MANIFEST.MF", budget)
	if err != nil {
		return nil, main, err
	}
	manifest, err := parseManifest(manifestData)
	if err != nil {
		return nil, main, err
	}
	if manifest["class-path"] != "" || strings.EqualFold(manifest["multi-release"], "true") {
		return nil, main, errors.New("manifest classpaths and multi-release archives are unsupported")
	}
	prefix := ""
	if executable {
		main = manifest["main-class"]
		switch main {
		case "org.springframework.boot.loader.JarLauncher", "org.springframework.boot.loader.launch.JarLauncher":
			main = manifest["start-class"]
			prefix = "BOOT-INF/classes/"
		case "org.springframework.boot.loader.PropertiesLauncher", "org.springframework.boot.loader.launch.PropertiesLauncher":
			return nil, main, errors.New("PropertiesLauncher is unsupported")
		}
	}
	member, err := classMember(main)
	if err != nil {
		return nil, main, err
	}
	data, err = readMember(z, prefix+member, budget)
	return data, main, err
}

func readMember(z *zip.Reader, name string, budget *int) ([]byte, error) {
	var match *zip.File
	for _, f := range z.File {
		if f.Name == name {
			if match != nil {
				return nil, fmt.Errorf("duplicate archive member %q", name)
			}
			match = f
		}
	}
	if match == nil {
		return nil, nil
	}
	limit := min(maxClassBytes, *budget)
	if !match.Mode().IsRegular() || match.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("unsafe or oversized member %q", name)
	}
	r, err := match.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("decompression limit exceeded")
	}
	*budget -= len(data)
	return data, nil
}

func parseManifest(data []byte) (map[string]string, error) {
	values := map[string]string{}
	var key string
	for line := range strings.SplitSeq(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") {
			if key == "" {
				return nil, errors.New("invalid manifest continuation")
			}
			values[key] += line[1:]
			continue
		}
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			return nil, errors.New("invalid manifest header")
		}
		key = strings.ToLower(name)
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate manifest header")
		}
		values[key] = value
	}
	return values, nil
}
