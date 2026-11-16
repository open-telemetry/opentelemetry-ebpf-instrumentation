// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxSinatraFileBytes int64 = 2 * 1024 * 1024
	maxSinatraFiles           = 256
)

var sinatraDeclaration = regexp.MustCompile(`^(get|post|put|patch|delete|head|options)\b\s*\(?\s*(.*)$`)

// sinatraSkipDirs lists directories that are unlikely to hold application
// route declarations, on top of the directories already excluded for every
// language by skipDirs.
var sinatraSkipDirs = map[string]struct{}{
	".bundle":  {},
	"coverage": {},
	"log":      {},
	"spec":     {},
	"test":     {},
	"tmp":      {},
	"vendor":   {},
}

// extractSinatraRoutes scans every Ruby file under dir for Sinatra route
// declarations (get/post/put/patch/delete/head/options). Unlike Rails,
// Sinatra has no single routing file such as config/routes.rb, so this is
// used as a fallback when extractRailsRoutes cannot find one: the whole
// application tree is walked instead, skipping common non-application
// directories, up to maxSinatraFiles.
func extractSinatraRoutes(ctx context.Context, dir string) ([]string, error) {
	var routes []string
	seen := map[string]struct{}{}
	err := walkRubyFiles(ctx, dir, func(path string) error {
		fileRoutes, err := scanSinatraRouteFile(ctx, path)
		if err != nil {
			return err
		}
		for _, route := range fileRoutes {
			if _, ok := seen[route]; !ok {
				seen[route] = struct{}{}
				routes = append(routes, route)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(routes)
	sortRouteFragments(routes)
	return routes, nil
}

// walkRubyFiles visits every .rb file under root, up to maxSinatraFiles,
// skipping directories unlikely to hold application code.
func walkRubyFiles(ctx context.Context, root string, fn func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scanned := 0
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			if path != root && skipSinatraDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() > maxSinatraFileBytes || filepath.Ext(path) != ".rb" {
			return nil
		}
		scanned++
		if err := fn(path); err != nil {
			return err
		}
		if scanned >= maxSinatraFiles {
			return filepath.SkipAll
		}
		return nil
	})
}

func skipSinatraDir(name string) bool {
	if _, ok := skipDirs[name]; ok {
		return true
	}
	_, ok := sinatraSkipDirs[name]
	return ok
}

func scanSinatraRouteFile(ctx context.Context, path string) ([]string, error) {
	file, _ := langtools.OpenMetadataFile(path, maxSinatraFileBytes)
	if file == nil {
		return nil, nil
	}
	defer file.Close()
	return scanSinatraRoutes(ctx, io.LimitReader(file, maxSinatraFileBytes))
}

// scanSinatraRoutes reads Sinatra route declarations, e.g.
//
//	get '/users/:id' do
//
// from a single Ruby source file without executing it. Placeholders like
// ":id" are preserved as-is: the route matcher already understands them.
func scanSinatraRoutes(ctx context.Context, reader io.Reader) ([]string, error) {
	var routes []string
	scanner := bufio.NewScanner(reader)
	// bufio.Scanner defaults to a 64KiB token limit; match it to the read
	// budget above so a single long line doesn't abort the scan with
	// ErrTooLong.
	scanner.Buffer(nil, int(maxSinatraFileBytes))
	inComment := false
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "=begin") {
			inComment = true
		}
		if inComment {
			if strings.HasPrefix(line, "=end") {
				inComment = false
			}
			continue
		}
		line = stripRailsComment(line)
		if line == "" {
			continue
		}
		declaration := sinatraDeclaration.FindStringSubmatch(line)
		if declaration == nil {
			continue
		}
		path, ok := railsLiteralValue(declaration[2])
		if !ok || path == "" {
			continue
		}
		path = ensureLeadingSlash(strings.Trim(path, "/"))
		// Optional segments, splats, and regex routes need matcher semantics
		// beyond literal fragments.
		if strings.ContainsAny(path, "()*") {
			continue
		}
		routes = append(routes, path)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	slices.Sort(routes)
	routes = slices.Compact(routes)
	sortRouteFragments(routes)
	return routes, nil
}
