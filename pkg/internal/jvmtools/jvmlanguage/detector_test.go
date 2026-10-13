// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmlanguage

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect(t *testing.T) {
	root := t.TempDir()
	for dir, marker := range map[string]string{
		"classes": "Lkotlin/Metadata;",
		"plain":   "",
		"scala":   "Lscala/reflect/ScalaSignature;",
		"tasty":   "TASTY",
	} {
		require.NoError(t, os.Mkdir(filepath.Join(root, dir), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, dir, "Example.class"), entryClass(marker), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "classes", "Wrong.class"), entryClass("Lkotlin/Metadata;"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "classes", "Broken.class"), []byte("invalid"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Example.java"), []byte("class Example {}"), 0o600))
	outside := filepath.Join(t.TempDir(), "Example.class")
	require.NoError(t, os.WriteFile(outside, entryClass("Lkotlin/Metadata;"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "classes", "Escape.class")))
	require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(root, "escape")))
	require.NoError(t, os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "dangling")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "broken.jar"), []byte("invalid"), 0o600))

	for _, jar := range []struct {
		name, manifest, member string
	}{
		{"app.jar", "Main-Class: Example\n\n", "Example.class"},
		{"boot.jar", "Main-Class: org.springframework.boot.loader.launch.JarLauncher\nStart-Class: Example\n\n", "BOOT-INF/classes/Example.class"},
		{"manifest-cp.jar", "Main-Class: Example\nClass-Path: other.jar\n\n", "Example.class"},
	} {
		var buf bytes.Buffer
		writer := zip.NewWriter(&buf)
		for name, data := range map[string][]byte{
			"META-INF/MANIFEST.MF": []byte(jar.manifest),
			jar.member:             entryClass("Lkotlin/Metadata;"),
		} {
			member, err := writer.Create(name)
			require.NoError(t, err)
			_, err = member.Write(data)
			require.NoError(t, err)
		}
		require.NoError(t, writer.Close())
		require.NoError(t, os.WriteFile(filepath.Join(root, jar.name), buf.Bytes(), 0o600))
	}

	for _, tt := range []struct {
		name, language, entry, errorText string
		args                             []string
		env                              map[string]string
	}{
		{name: "kotlin directory", language: "kotlin", entry: "Example", args: []string{"-cp", "/classes", "Example"}},
		{name: "scala 2 directory", language: "scala", entry: "Example", args: []string{"-cp", "/scala", "Example"}},
		{name: "scala 3 directory", language: "scala", entry: "Example", args: []string{"-cp", "/tasty", "Example"}},
		{name: "default classpath", language: "kotlin", entry: "Example", args: []string{"Example"}},
		{name: "environment classpath", language: "scala", entry: "Example", args: []string{"Example"}, env: map[string]string{"CLASSPATH": "/scala"}},
		{name: "first class wins", entry: "Example", args: []string{"-cp", "/plain:/classes", "Example"}},
		{name: "skip directory without entry", language: "kotlin", entry: "Example", args: []string{"-cp", "/:/classes", "Example"}},
		{name: "skip missing directory", language: "kotlin", entry: "Example", args: []string{"-cp", "/missing:/classes", "Example"}},
		{name: "skip missing parent directories", language: "kotlin", entry: "Example", args: []string{"-cp", "/missing/nested:/classes", "Example"}},
		{name: "skip missing relative directory", language: "kotlin", entry: "Example", args: []string{"-cp", "missing:.", "Example"}},
		{name: "skip missing classpath jar", language: "kotlin", entry: "Example", args: []string{"-cp", "/missing.jar:/classes", "Example"}},
		{name: "all classpath roots missing", errorText: "entry class not found", args: []string{"-cp", "/missing:/other", "Example"}},
		{name: "missing executable jar", errorText: "unresolvable classpath root", args: []string{"-jar", "/missing.jar"}},
		{name: "unsafe classpath root", errorText: "unresolvable classpath root", args: []string{"-cp", "/escape:/classes", "Example"}},
		{name: "missing path below unsafe root", errorText: "unresolvable classpath root", args: []string{"-cp", "/escape/missing:/classes", "Example"}},
		{name: "dangling classpath symlink", errorText: "unresolvable classpath root", args: []string{"-cp", "/dangling:/classes", "Example"}},
		{name: "missing path below dangling symlink", errorText: "unresolvable classpath root", args: []string{"-cp", "/dangling/missing:/classes", "Example"}},
		{name: "malformed classpath archive", errorText: "not a valid zip file", args: []string{"-cp", "/broken.jar:/classes", "Example"}},
		{name: "application arguments", language: "kotlin", entry: "Example", args: []string{"Example", "-jar", "/missing.jar"}},
		{name: "executable jar", language: "kotlin", entry: "Example", args: []string{"-jar", "/app.jar"}},
		{name: "spring boot jar", language: "kotlin", entry: "Example", args: []string{"-jar", "/boot.jar"}},
		{name: "source launch", language: "java", args: []string{"/Example.java"}},
		{name: "missing source", errorText: "unreadable source entry", args: []string{"/Missing.java"}},
		{name: "missing class", errorText: "entry class not found", args: []string{"Missing"}},
		{name: "mismatched class", errorText: "class identity", args: []string{"Wrong"}},
		{name: "malformed class", errorText: "invalid class file magic", args: []string{"Broken"}},
		{name: "symlink escape", errorText: "unsafe class path", args: []string{"Escape"}},
		{name: "manifest classpath", errorText: "manifest classpaths", args: []string{"-jar", "/manifest-cp.jar"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Detect(root, "/classes", tt.args, tt.env)
			if tt.errorText != "" {
				require.ErrorContains(t, err, tt.errorText)
				assert.Empty(t, result.Language)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.language, result.Language)
			assert.Equal(t, tt.entry, result.EntryClass)
			if tt.language == "" {
				assert.NotEmpty(t, result.Reason)
				assert.Empty(t, result.Evidence)
			} else {
				assert.NotEmpty(t, result.Evidence)
			}
		})
	}
}

// Minimal class structures keep these tests independent of compiler installations.
func entryClass(marker string) []byte {
	data := binary.BigEndian.AppendUint32(nil, 0xCAFEBABE)
	for _, value := range []uint16{0, 52, 7} {
		data = binary.BigEndian.AppendUint16(data, value)
	}
	attributeName := "RuntimeVisibleAnnotations"
	attributeData := []byte{0, 1, 0, 6, 0, 0}
	if marker == "TASTY" {
		attributeName = "TASTY"
		attributeData = make([]byte, 16)
	}
	for i, value := range []string{"Example", "", "java/lang/Object", "", attributeName, marker} {
		if i == 1 || i == 3 {
			data = append(data, 7) // CONSTANT_Class references the preceding UTF-8 entry.
			data = binary.BigEndian.AppendUint16(data, uint16(i))
			continue
		}
		data = append(data, 1)
		data = binary.BigEndian.AppendUint16(data, uint16(len(value)))
		data = append(data, value...)
	}
	for _, value := range []uint16{1, 2, 4, 0, 0, 0} {
		data = binary.BigEndian.AppendUint16(data, value)
	}
	if marker == "" {
		return binary.BigEndian.AppendUint16(data, 0)
	}
	data = binary.BigEndian.AppendUint16(data, 1)
	data = binary.BigEndian.AppendUint16(data, 5)
	data = binary.BigEndian.AppendUint32(data, uint32(len(attributeData)))
	return append(data, attributeData...)
}

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
