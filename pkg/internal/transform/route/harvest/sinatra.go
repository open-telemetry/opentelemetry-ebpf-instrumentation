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
	maxGemfileBytes     int64 = 2 * 1024 * 1024
)

var sinatraDeclaration = regexp.MustCompile(`^(get|post|put|patch|delete|head|options)\b\s*\(?\s*(.*)$`)

// sinatraLiteral matches a quoted string path followed by an argument
// boundary. Unlike railsLiteral it rejects symbols: Sinatra paths are strings
// (or regexps), so a symbol argument is something else, such as the status in
// "head :ok" or a Padrino named route like "get :index".
var sinatraLiteral = regexp.MustCompile(`^(?:'([^'\\]*)'|"([^"\\#]*)")\s*(?:,|\)|do\b|$)`)

// Bundler manifests, with the lockfile ahead of the file it is resolved from.
// gems.rb and gems.locked are the alternative names Bundler accepts.
var (
	bundlerLockfiles = [...]string{"Gemfile.lock", "gems.locked"}
	bundlerGemfiles  = [...]string{"Gemfile", "gems.rb"}

	// A resolved or direct dependency in a lockfile: "    sinatra (4.1.1)",
	// "  sinatra (~> 4.0)" or "  sinatra!".
	sinatraLockedGem = regexp.MustCompile(`(?m)^[ \t]+sinatra(?:!|[ \t]|\r?$)`)
	// A gem declaration in a Gemfile: gem 'sinatra' or gem("sinatra", ...).
	sinatraGemfileGem = regexp.MustCompile(`^gem\b\s*\(?\s*['"]sinatra['"]`)
)

// sinatraOptionalParam matches a named parameter marked optional with "?",
// e.g. ":id?".
var sinatraOptionalParam = regexp.MustCompile(`(:\w+)\?`)

// sinatraSkipDirs lists the Ruby specific directories that are unlikely to
// hold application route declarations, on top of commonSkipDirs. The system
// directories of skipDirs are left out on purpose: the scan never starts at
// the file system root, and names such as lib commonly hold Sinatra
// application code.
var sinatraSkipDirs = map[string]struct{}{
	".bundle":      {},
	"coverage":     {},
	"log":          {},
	"node_modules": {},
	"spec":         {},
	"test":         {},
	"tmp":          {},
	"vendor":       {},
}

// dependsOnSinatra reports whether the Bundler manifest closest to dir, looking
// no further up than root, lists the sinatra gem. Any Ruby web framework can
// use bare get/post declarations (Grape's "get ':id' do", for instance), so
// the Sinatra scan only runs for applications that depend on Sinatra, the
// same way the PHP harvester checks composer.json.
func dependsOnSinatra(ctx context.Context, root, dir string) (bool, error) {
	depends := false
	err := langtools.WalkParentDirectories(dir, root, func(dir string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		found := false
		for _, name := range bundlerLockfiles {
			if data, ok := readBundlerManifest(root, dir, name); ok {
				found = true
				depends = depends || sinatraLockedGem.Match(data)
			}
		}
		for _, name := range bundlerGemfiles {
			if data, ok := readBundlerManifest(root, dir, name); ok {
				found = true
				depends = depends || gemfileListsSinatra(data)
			}
		}
		// The nearest manifest describes the application: stop there.
		return found, nil
	})
	return depends, err
}

func readBundlerManifest(root, dir, name string) ([]byte, bool) {
	relative, err := filepath.Rel(root, filepath.Join(dir, name))
	if err != nil {
		return nil, false
	}
	path, ok := langtools.ResolveProcessPath(root, "/", relative)
	if !ok {
		return nil, false
	}
	data, _, err := langtools.ReadMetadataFile(path, maxGemfileBytes)
	if err != nil || data == nil {
		return nil, false
	}
	return data, true
}

func gemfileListsSinatra(data []byte) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		if sinatraGemfileGem.MatchString(stripRailsComment(strings.TrimSpace(line))) {
			return true
		}
	}
	return false
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
	if _, ok := commonSkipDirs[name]; ok {
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
		literal := sinatraLiteral.FindStringSubmatch(declaration[2])
		if literal == nil {
			continue
		}
		path := literal[1] + literal[2]
		if path == "" {
			continue
		}
		path, ok := resolveSinatraOptionals(path)
		if !ok {
			continue
		}
		path = ensureLeadingSlash(strings.Trim(path, "/"))
		// Optional groups, splats, and regex routes need matcher semantics
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

// resolveSinatraOptionals resolves the Sinatra "?" modifier, which makes the
// preceding slash or named parameter optional:
//
//	/posts/?    -> /posts
//	/posts/:id? -> /posts/:id
//
// It returns false for any other use of "?" (such as an optional literal
// character), which needs matcher semantics beyond literal fragments.
func resolveSinatraOptionals(path string) (string, bool) {
	if !strings.Contains(path, "?") {
		return path, true
	}
	path = sinatraOptionalParam.ReplaceAllString(path, "$1")
	path = strings.ReplaceAll(path, "/?", "/")
	return path, !strings.Contains(path, "?")
}
