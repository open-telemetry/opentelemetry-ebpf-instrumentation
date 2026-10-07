// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmlanguage

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLaunchBoundary(t *testing.T) {
	args := []string{"-cp", "classes", "example.Main", "-jar", "not-the-launch.jar"}
	got, err := parseLaunch(args, nil)
	if err != nil || got.main != "example.Main" || !reflect.DeepEqual(got.vmArgs, args[:2]) {
		t.Fatalf("%+v %v", got, err)
	}
	for _, args := range [][]string{{"@args"}, {"-m", "app/Main"}, {"--module-path", "mods", "Main"}, {"-javaagent:agent.jar", "Main"}, {"-cp"}, {"--unknown", "Main"}} {
		if _, err := parseLaunch(args, nil); err == nil {
			t.Fatalf("accepted unsupported launch %v", args)
		}
	}
	if _, err := parseLaunch([]string{"Main"}, map[string]string{"JDK_JAVA_OPTIONS": "-cp override"}); err == nil {
		t.Fatal("ignored launcher environment")
	}
}

func TestManifestMainSection(t *testing.T) {
	got, err := parseManifest([]byte("Manifest-Version: 1.0\r\nMain-Class: example.\r\n Main\r\n\r\nName: file\r\nMain-Class: Wrong\r\n"))
	if err != nil || got["main-class"] != "example.Main" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := parseManifest([]byte("Main-Class: One\nMain-Class: Two\n")); err == nil {
		t.Fatal("accepted duplicate")
	}
}

func TestArchiveLimitsAndAmbiguity(t *testing.T) {
	for _, tt := range []struct {
		name      string
		duplicate bool
		oversized bool
	}{
		{name: "duplicate", duplicate: true}, {name: "oversized", oversized: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			data := []byte("not a class")
			if tt.oversized {
				data = make([]byte, maxClassBytes+1)
			}
			count := 1
			if tt.duplicate {
				count = 2
			}
			for range count {
				f, err := w.Create("Example.class")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "app.jar")
			if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			budget := maxTotalBytes
			if _, _, err := readArchiveClass(path, "Example", false, &budget); err == nil {
				t.Fatal("accepted unsafe archive")
			}
		})
	}
}

func TestClassPathTraversal(t *testing.T) {
	for _, name := range []string{"../Main", "/Main", "a..Main", "a\\Main", "[Main"} {
		if _, err := classMember(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
