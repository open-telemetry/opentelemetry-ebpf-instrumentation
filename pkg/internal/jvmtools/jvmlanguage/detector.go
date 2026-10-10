// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmlanguage // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvmlanguage"

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"
)

const (
	maxClassBytes   = java.MaxClassBytes
	maxArchiveBytes = 16 * 1024 * 1024
	maxTotalBytes   = 32 * 1024 * 1024
	maxRoots        = 32
)

// Result keeps uncertainty out of the exported language value.
type Result struct {
	Language   string
	EntryClass string
	Evidence   []string
	Reason     string
}

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
		if f.Name != name {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("duplicate archive member %q", name)
		}
		match = f
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

	data, main, err := findEntryClass(root, cwd, l, env)
	if err != nil {
		return Result{}, err
	}
	marker, err := java.InspectLanguage(data)
	if err != nil {
		return Result{}, err
	}
	if marker.Class != strings.ReplaceAll(main, ".", "/") {
		return Result{}, errors.New("class identity does not match entry point")
	}

	result := Result{Language: marker.Language, EntryClass: main, Evidence: marker.Markers}
	if result.Language == "" {
		result.Reason = "no recognized compiler marker; Java is not inferred"
	}
	return result, nil
}

func findEntryClass(root, cwd string, l launch, env map[string]string) ([]byte, string, error) {
	cp := jvmtools.ParseJavaLaunch(l.vmArgs, env)
	if strings.Contains(cp.Classpath, "*") {
		return nil, l.main, errors.New("wildcard classpaths are unsupported in this PoC")
	}
	if cp.Classpath == "" {
		cp.Classpath = cwd
	}
	entries := filepath.SplitList(cp.Classpath)
	if l.jar != "" {
		entries = []string{l.jar}
	}
	if len(entries) > maxRoots {
		return nil, l.main, errors.New("classpath root limit exceeded")
	}
	budget := maxTotalBytes
	for _, entry := range entries {
		if entry == "" {
			entry = cwd
		}
		path, info, ok := langtools.StatProcessPath(root, cwd, entry)
		if !ok {
			// The JVM skips missing classpath entries; executable JARs must exist.
			if l.jar == "" && isMissingClasspathEntry(root, cwd, entry) {
				continue
			}
			return nil, l.main, fmt.Errorf("unresolvable classpath root %q", entry)
		}
		var (
			data []byte
			err  error
		)
		if info.IsDir() {
			if l.jar != "" {
				return nil, l.main, errors.New("jar path is a directory")
			}
			data, err = readDirectoryClass(root, cwd, entry, path, l.main)
		} else {
			data, l.main, err = readArchiveClass(path, l.main, l.jar != "", &budget)
		}
		if err != nil {
			return nil, l.main, err
		}
		if data == nil {
			continue
		}
		return data, l.main, nil
	}
	return nil, l.main, errors.New("entry class not found")
}

func isMissingClasspathEntry(root, cwd, entry string) bool {
	entry = langtools.AbsoluteProcessPath(cwd, entry)
	for filepath.IsAbs(entry) {
		parent := filepath.Dir(entry)
		if parent == entry {
			return false
		}
		path, ok := langtools.ResolveProcessPath(root, cwd, parent)
		if ok {
			// Do not mistake a dangling or escaping symlink for a missing entry.
			_, err := os.Lstat(filepath.Join(path, filepath.Base(entry)))
			return errors.Is(err, os.ErrNotExist)
		}
		entry = parent
	}
	return false
}

func readDirectoryClass(root, cwd, entry, path, main string) ([]byte, error) {
	member, err := classMember(main)
	if err != nil {
		return nil, err
	}
	_, err = os.Lstat(filepath.Join(path, member))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	classPath, ok := langtools.ResolveProcessPath(root, cwd, filepath.Join(entry, member))
	if !ok {
		return nil, fmt.Errorf("unsafe class path %q", main)
	}
	data, _, err := langtools.ReadMetadataFile(classPath, maxClassBytes)
	if err != nil || data == nil {
		return nil, fmt.Errorf("cannot read class %q safely", main)
	}
	return data, nil
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

type launch struct {
	main   string
	jar    string
	source bool
	vmArgs []string
}

// parseLaunch accepts a deliberately small subset of the Java launcher grammar.
func parseLaunch(args []string, env map[string]string) (launch, error) {
	for _, key := range []string{"JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"} {
		if env[key] != "" {
			return launch{}, fmt.Errorf("unsupported launcher environment: %s", key)
		}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-cp" || arg == "-classpath" || arg == "--class-path":
			if i+1 >= len(args) || args[i+1] == "" {
				return launch{}, fmt.Errorf("missing value for %s", arg)
			}
			i++
		case strings.HasPrefix(arg, "--class-path="):
			if arg == "--class-path=" {
				return launch{}, errors.New("empty explicit classpath is unsupported")
			}
		case arg == "-jar":
			if i+1 >= len(args) {
				return launch{}, errors.New("missing jar path")
			}
			return launch{jar: args[i+1], vmArgs: args[:i+2]}, nil
		case strings.HasPrefix(arg, "-D"):
			if strings.HasPrefix(arg, "-Djava.system.class.loader") || strings.HasPrefix(arg, "-Dloader.") || strings.HasPrefix(arg, "-Djava.class.path") || strings.HasPrefix(arg, "-Dsun.boot.class.path") {
				return launch{}, fmt.Errorf("unsupported class loader option %q", arg)
			}
		case strings.HasPrefix(arg, "-Xmx"), strings.HasPrefix(arg, "-Xms"), strings.HasPrefix(arg, "-Xss"), arg == "-server", arg == "-client", arg == "-ea", arg == "-da":
		case strings.HasPrefix(arg, "-"), strings.HasPrefix(arg, "@"):
			return launch{}, fmt.Errorf("unsupported launcher option %q", arg)
		default:
			if arg == "" {
				return launch{}, errors.New("empty entry point")
			}
			return launch{main: arg, source: strings.HasSuffix(arg, ".java"), vmArgs: args[:i]}, nil
		}
	}
	return launch{}, errors.New("missing entry point")
}

const maxProcessBytes = 2 * 1024 * 1024

// DetectPID performs passive Linux /proc inspection. It does not attach to the JVM.
func DetectPID(pid int) (Result, error) {
	if pid <= 0 {
		return Result{}, errors.New("invalid PID")
	}
	proc := "/proc/" + strconv.Itoa(pid)
	executable, err := os.Readlink(proc + "/exe")
	if err != nil || filepath.Base(executable) != "java" {
		return Result{}, errors.New("only standard java launcher processes are supported")
	}
	start, err := procs.StartTime(app.PID(pid))
	if err != nil {
		return Result{}, err
	}
	maps, err := readProcessFile(proc + "/maps")
	if err != nil {
		return Result{}, err
	}
	if !strings.Contains(string(maps), "/libjvm.so") {
		return Result{}, errors.New("process has no observed libjvm.so mapping")
	}
	cmd, err := readProcessFile(proc + "/cmdline")
	if err != nil {
		return Result{}, err
	}
	args := strings.Split(strings.TrimSuffix(string(cmd), "\x00"), "\x00")
	if len(args) < 2 {
		return Result{}, errors.New("missing Java launch arguments")
	}
	environ, err := readProcessFile(proc + "/environ")
	if err != nil {
		return Result{}, err
	}
	env := map[string]string{}
	for value := range strings.SplitSeq(string(environ), "\x00") {
		key, value, ok := strings.Cut(value, "=")
		if ok {
			env[key] = value
		}
	}
	cwd, err := os.Readlink(proc + "/cwd")
	if err != nil {
		return Result{}, err
	}
	result, err := Detect(proc+"/root", cwd, args[1:], env)
	if err != nil {
		return Result{}, err
	}
	// Recheck identity before returning evidence from this process.
	after, err := procs.StartTime(app.PID(pid))
	if err != nil || after != start {
		return Result{}, errors.New("process exited or PID was reused during inspection")
	}
	afterCmd, err := readProcessFile(proc + "/cmdline")
	if err != nil || !bytes.Equal(cmd, afterCmd) {
		return Result{}, errors.New("process launch changed during inspection")
	}
	return result, nil
}

func readProcessFile(path string) ([]byte, error) {
	data, _, err := langtools.ReadMetadataFile(path, maxProcessBytes)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("cannot read process metadata %q", path)
	}
	return data, nil
}
