// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
	"unicode/utf8"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	pythonMaxSourceFile   = 1 << 20
	pythonMaxSourceLine   = 4096
	pythonSourceCacheSize = 512
	pythonSourceTimeout   = 100 * time.Millisecond

	// /proc/<pid>/status lists the real, effective, saved and filesystem ids.
	pythonFilesystemID = 3

	pythonReadPerm   fs.FileMode = 0o4
	pythonSearchPerm fs.FileMode = 0o1
	pythonOwnerShift             = 6
	pythonGroupShift             = 3

	utf8BOM = "\ufeff"
)

// pythonSourceRoot names the process whose filesystem and credentials source
// lines are read with. An empty dir reads none.
type pythonSourceRoot struct {
	pid app.PID
	dir string
}

// pythonSourceRef is a line of a file, as a frame names them.
type pythonSourceRef struct {
	file string
	line uint32
}

// pythonSourceVersion identifies one version of a file. linecache also treats
// a file as changed when its size or modification time changes.
type pythonSourceVersion struct {
	device, inode  uint64
	size, modified int64
}

type pythonSourceKey struct {
	version pythonSourceVersion
	line    uint32
}

var pythonSourceCache, _ = lru.New[pythonSourceKey, string](pythonSourceCacheSize)

// pythonSourceSlot admits one read at a time. A read stalled on a mount keeps
// it, so later tracebacks go without source lines instead of waiting.
var pythonSourceSlot = make(chan struct{}, 1)

// pythonSourceLines returns the lines of refs as traceback prints them, read
// from the raising process's filesystem. Unavailable lines are missing.
func pythonSourceLines(root pythonSourceRoot, refs []pythonSourceRef) map[pythonSourceRef]string {
	if root.dir == "" || !slices.ContainsFunc(refs, pythonSourceReadable) {
		return nil
	}
	select {
	case pythonSourceSlot <- struct{}{}:
	default:
		return nil
	}

	done := make(chan map[pythonSourceRef]string, 1)
	go func() {
		defer func() { <-pythonSourceSlot }()
		done <- readPythonSourceLines(root, refs)
	}()
	select {
	case lines := <-done:
		return lines
	case <-time.After(pythonSourceTimeout):
		return nil
	}
}

func pythonSourceReadable(ref pythonSourceRef) bool {
	return filepath.IsAbs(ref.file)
}

// pythonCredentials are the filesystem ids the kernel checks file access with,
// as OBI's user namespace sees them.
type pythonCredentials struct {
	uid, gid uint32
}

func readPythonSourceLines(root pythonSourceRoot, refs []pythonSourceRef) map[pythonSourceRef]string {
	process, err := procfs.NewProc(int(root.pid))
	if err != nil {
		return nil
	}
	status, err := process.NewStatus()
	if err != nil {
		return nil
	}
	credentials := pythonCredentials{
		uid: uint32(status.UIDs[pythonFilesystemID]),
		gid: uint32(status.GIDs[pythonFilesystemID]),
	}

	wanted := map[string][]uint32{}
	for _, ref := range refs {
		if pythonSourceReadable(ref) {
			wanted[ref.file] = append(wanted[ref.file], ref.line)
		}
	}
	lines := map[pythonSourceRef]string{}
	for name, numbers := range wanted {
		readPythonSourceFile(root.dir, credentials, name, numbers, lines)
	}
	return lines
}

// readPythonSourceFile reads a file at most once, and only for lines missing
// from the cache.
func readPythonSourceFile(root string, credentials pythonCredentials, name string, numbers []uint32, lines map[pythonSourceRef]string) {
	file, version, ok := openPythonSourceFile(root, credentials, name)
	if !ok {
		return
	}
	defer file.Close()

	var data []byte
	read := false
	for _, number := range numbers {
		key := pythonSourceKey{version: version, line: number}
		text, ok := pythonSourceCache.Get(key)
		if !ok {
			if !read {
				var err error
				if data, err = io.ReadAll(io.LimitReader(file, pythonMaxSourceFile)); err != nil {
					return
				}
				read = true
			}
			text = pythonSourceText(data, number)
			pythonSourceCache.Add(key, text)
		}
		lines[pythonSourceRef{file: name, line: number}] = text
	}
}

// openPythonSourceFile opens a file only when the process could read it, and
// only if it is still the file that was resolved and checked.
func openPythonSourceFile(root string, credentials pythonCredentials, name string) (*os.File, pythonSourceVersion, bool) {
	path, resolved, ok := langtools.StatProcessPath(root, "/", name)
	if !ok || !credentials.searches(root, filepath.Dir(path)) {
		return nil, pythonSourceVersion{}, false
	}
	file, _ := langtools.OpenMetadataFile(path, pythonMaxSourceFile)
	if file == nil {
		return nil, pythonSourceVersion{}, false
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(resolved, info) || !credentials.permits(info, pythonReadPerm) {
		file.Close()
		return nil, pythonSourceVersion{}, false
	}
	version, ok := pythonSourceFileVersion(info)
	if !ok {
		file.Close()
		return nil, pythonSourceVersion{}, false
	}
	return file, version, true
}

// searches reports whether the process can search every directory from root
// down to dir.
func (c pythonCredentials) searches(root, dir string) bool {
	searchable := true
	_ = langtools.WalkParentDirectories(dir, root, func(dir string) (bool, error) {
		info, err := os.Stat(dir)
		searchable = err == nil && c.permits(info, pythonSearchPerm)
		return !searchable, nil
	})
	return searchable
}

// permits checks the mode bits as the kernel does, where access is given as the
// bits for others. Supplementary groups are not known, so access through the
// bits for others also needs the group bits. ACLs, security modules and
// capabilities other than root's are not modeled.
func (c pythonCredentials) permits(info fs.FileInfo, access fs.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := info.Mode().Perm()
	switch {
	case c.uid == 0:
		return true
	case stat.Uid == c.uid:
		return mode&(access<<pythonOwnerShift) != 0
	case stat.Gid == c.gid:
		return mode&(access<<pythonGroupShift) != 0
	}
	return mode&(access<<pythonGroupShift) != 0 && mode&access != 0
}

// pythonSourceText returns a line stripped, splitting lines as Python's
// universal newlines do. A line past the end, too long or not UTF-8 is "".
func pythonSourceText(data []byte, line uint32) string {
	data = bytes.TrimPrefix(data, []byte(utf8BOM))
	for current := uint32(1); ; current++ {
		end := bytes.IndexAny(data, "\r\n")
		if end < 0 {
			end = len(data)
		}
		if current == line {
			text := bytes.TrimSpace(data[:end])
			if len(text) > pythonMaxSourceLine || !utf8.Valid(text) {
				return ""
			}
			return string(text)
		}
		if end == len(data) {
			return ""
		}

		next := end + 1
		if data[end] == '\r' && next < len(data) && data[next] == '\n' {
			next++
		}
		data = data[next:]
	}
}
