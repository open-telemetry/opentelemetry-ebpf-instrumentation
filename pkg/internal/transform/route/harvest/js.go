// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

// MaxJSFileScanBytes caps opportunistic JS/TS source scans to avoid spending
// unbounded work on large application files.
const MaxJSFileScanBytes int64 = 10 * 1024 * 1024

// /root is purposefully missing, since we need it to star the file walk
// we skip later any root directories we find that don't match our original
// path
var skipDirs = map[string]string{
	// Linux root file system
	"bin":        "Essential command binaries",
	"boot":       "Boot loader files",
	"dev":        "Device files",
	"etc":        "System configuration files",
	"home":       "User home directories",
	"lib":        "Essential shared libraries",
	"lib64":      "64-bit libraries",
	"media":      "Removable media mount points",
	"mnt":        "Temporary mount points",
	"opt":        "Optional software packages",
	"proc":       "Process and kernel information",
	"run":        "Runtime data",
	"sbin":       "System binaries",
	"srv":        "Service data",
	"sys":        "Kernel and device information",
	"tmp":        "Temporary files",
	"usr":        "User programs and data",
	"var":        "Variable data",
	"lost+found": "Recovered files",
	"snap":       "Snap packages",
	"flatpak":    "Flatpak packages",
	"ostree":     "Used by rpm-ostree/Fedora Silverblue for atomic updates",
	"sysroot":    "Used in some immutable/atomic variants as the actual root filesystem",
	// Node specific
	"node_modules": "Standard node modules",
	".npm":         "npm build cache",
	".git":         "git source control",
	"dist":         "distribution directories",
	"build":        "build directories",
	".next":        "Next.js output/metadata directory",
}

// RoutePattern represents an extracted HTTP route
type RoutePattern struct {
	Method  string
	Path    string
	File    string
	Line    int
	Handler string
}

// FrameworkPatterns holds regex patterns for different Node.js frameworks
type FrameworkPatterns struct {
	// Express, Koa, Fastify short: app.get('/path', handler), router.post('/path', handler)
	Typical *regexp.Regexp
	// Express route chaining: .route('/path').get(handler).post(handler)
	ExpressRoute *regexp.Regexp
	// Fastify: fastify.get('/path', handler), fastify.route({ method: 'GET', url: '/path' })
	FastifyShort *regexp.Regexp
	FastifyRoute *regexp.Regexp
	// Koa Router: router.get('/path', handler)
	KoaRouter *regexp.Regexp
	// Hapi: server.route({ method: 'GET', path: '/path' })
	Hapi *regexp.Regexp
	// Restify: server.get('/path', handler)
	Restify *regexp.Regexp
	// NestJS decorators: @Get('/path'), @Post('/path')
	NestJS *regexp.Regexp
	// NestJS controller decorator: @Controller('prefix'), @Controller()
	NestJSController *regexp.Regexp
	// NestJS decorators in compiled output: (0, common_1.Get)('store')
	CompiledNestMethod *regexp.Regexp
	// NestJS controller decorator in compiled output: (0, common_1.Controller)('invoice')
	CompiledNestController *regexp.Regexp
	// HTTPDispatcher: dispatcher.onGet('/path', ...), dispatcher.onPost(/^\/ratings\/[0-9]*/, ...)
	HTTPDispatcher *regexp.Regexp
	// Fallback
	Fallback *regexp.Regexp

	// Path Cleanup regexes
	RegexPattern         *regexp.Regexp
	MultipleSlashPattern *regexp.Regexp
	CleanID              *regexp.Regexp
	// ValidPathChars matches valid URL path characters per RFC 3986
	// Includes: unreserved (A-Za-z0-9-._~)
	ValidPathChars *regexp.Regexp
}

// nextRoutesManifest is a partial representation of .next/routes-manifest.json.
type nextRoutesManifest struct {
	DynamicRoutes []struct {
		Page string `json:"page"`
	} `json:"dynamicRoutes"`
	StaticRoutes []struct {
		Page string `json:"page"`
	} `json:"staticRoutes"`
}

func newFrameworkPatterns() *FrameworkPatterns {
	return &FrameworkPatterns{
		// Matches: app.get('/users/:id', ...), router.post("/items", ...)
		Typical: regexp.MustCompile(`\.(get|post|put|patch|delete|head|options|all)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: .route('/path')
		ExpressRoute: regexp.MustCompile(`\.route\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]\s*\)`),

		// Matches: fastify.route({ method: 'GET', url: '/path' })
		FastifyRoute: regexp.MustCompile(`\.route\s*\(\s*\{[^}]*method:\s*['"\x60](\w+)['"\x60][^}]*url:\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: server.route({ method: 'GET', path: '/users/{id}' })
		Hapi: regexp.MustCompile(`\.route\s*\(\s*\{[^}]*method:\s*['"](\w+)['"][^}]*path:\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: server.get('/path', ...), server.post('/users/:id', ...)
		Restify: regexp.MustCompile(`\.(get|post|put|patch|del|head|opts)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: @Get('/users/:id'), @Post('/items'), and bare decorators such
		// as @Post(), which NestJS routes at the controller prefix
		NestJS: regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(\s*(?:['"\x60]([^'"\x60]*?)['"\x60]\s*)?\)`),

		// Matches: @Controller('users'), @Controller("api/v1/posts"), @Controller()
		NestJSController: regexp.MustCompile(`@Controller\s*\(\s*(?:['"\x60]([^'"\x60]*)['"\x60])?\s*\)`),

		// TypeScript compilers lower decorators to helper calls referencing the
		// decorator factory through the imported module object:
		//   (0, common_1.Get)('store')   tsc
		//   (0, _common.Get)(':id')      swc
		//   common_1.Get('store')        direct emit
		// The class association ("which @Controller() prefixes this @Get()?") is
		// scattered across __decorate() blocks, so compiled matches are harvested
		// as route fragments and matched partially instead of joined.
		CompiledNestMethod:     regexp.MustCompile(`[\w$]+\.(Get|Post|Put|Patch|Delete|Options|Head|All)\)?\s*\(\s*(?:['"\x60]([^'"\x60]*)['"\x60]\s*)?\)`),
		CompiledNestController: regexp.MustCompile(`[\w$]+\.Controller\)?\s*\(\s*(?:['"\x60]([^'"\x60]*)['"\x60]\s*)?\)`),

		// Matches: dispatcher.onGet('/path', ...), dispatcher.onPost(/^\/ratings\/[0-9]*/, ...)
		// Supports both string literals and regex literals
		HTTPDispatcher: regexp.MustCompile(`\.on(Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*(?:['"\x60]([^'"\x60]+)['"\x60]|/((?:[^\\,]|\\.)+))`),

		// Fallback (e.g. NextJS)
		Fallback: regexp.MustCompile(`['"\x60](/[^'"\x60]+)['"\x60]`),

		// Cleanup
		RegexPattern:         regexp.MustCompile(`[\\^$]`),
		MultipleSlashPattern: regexp.MustCompile(`//+`),
		ValidPathChars:       regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`),
		CleanID:              regexp.MustCompile(`[^A-Za-z0-9\-._]+`),
	}
}

type RouteExtractor struct {
	log      *slog.Logger
	patterns *FrameworkPatterns
	routes   []RoutePattern

	// nestPrefix is the path prefix of the NestJS @Controller() decorator most
	// recently seen in the file being scanned. TypeScript decorators always live
	// in the same file as the class they decorate, with @Controller() preceding
	// the method decorators, so tracking the last seen prefix per file is enough
	// to resolve the full route of each method decorator.
	nestPrefix string

	// compiled switches the scan to compiled-output mode: decorators lowered by
	// tsc/swc are recognized and harvested as route fragments (prefix/path
	// association is lost in compiled code), and the fallback pattern is
	// disabled because compiled code is full of path-like string literals.
	compiled bool
}

func NewRouteExtractor() *RouteExtractor {
	return &RouteExtractor{
		patterns: newFrameworkPatterns(),
		routes:   []RoutePattern{},
		log:      slog.With("component", "route.harvester.js"),
	}
}

// NewCompiledRouteExtractor returns an extractor for compiled/transpiled output
// (e.g. a NestJS app shipping only dist/). Its routes are fragments meant for
// partial matching.
func NewCompiledRouteExtractor() *RouteExtractor {
	e := NewRouteExtractor()
	e.compiled = true
	return e
}

func (e *RouteExtractor) expressPendingRoute(filePath, line string, lineNum int) bool {
	if matches := e.patterns.ExpressRoute.FindStringSubmatch(line); len(matches) > 1 {
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   matches[1],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

func (e *RouteExtractor) handleTypicalRoute(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Typical.FindStringSubmatch(line); len(matches) > 2 {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

func (e *RouteExtractor) handleFastifyRoute(filePath, line string, lineNum int) bool {
	if matches := e.patterns.FastifyRoute.FindStringSubmatch(line); len(matches) > 2 {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}

	return false
}

func (e *RouteExtractor) handleHapi(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Hapi.FindStringSubmatch(line); len(matches) > 2 {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

func (e *RouteExtractor) handleRestify(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Restify.FindStringSubmatch(line); len(matches) > 2 {
		method := matches[1]
		// Normalize restify methods: del -> DELETE, opts -> OPTIONS
		switch method {
		case "del":
			method = "delete"
		case "opts":
			method = "options"
		}
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(method),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

// handleNestJSController tracks the route prefix of the current NestJS
// @Controller() decorator, which applies to every method decorator that
// follows it in the same file.
func (e *RouteExtractor) handleNestJSController(line string) bool {
	if matches := e.patterns.NestJSController.FindStringSubmatch(line); matches != nil {
		e.nestPrefix = matches[1]
		return true
	}
	return false
}

// joinNestPaths combines a NestJS controller prefix with a method decorator
// path into a single absolute route, normalizing slashes. NestJS treats both
// parts as relative regardless of leading/trailing slashes.
func joinNestPaths(prefix, path string) string {
	prefix = strings.Trim(prefix, "/")
	path = strings.Trim(path, "/")
	switch {
	case prefix == "":
		return "/" + path
	case path == "":
		return "/" + prefix
	default:
		return "/" + prefix + "/" + path
	}
}

func (e *RouteExtractor) handleNestJS(filePath, line string, lineNum int) bool {
	if matches := e.patterns.NestJS.FindStringSubmatch(line); len(matches) > 2 {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   joinNestPaths(e.nestPrefix, matches[2]),
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}

	return false
}

// handleCompiledNestController harvests the prefix of a compiled @Controller()
// decorator as a standalone route fragment.
func (e *RouteExtractor) handleCompiledNestController(filePath, line string, lineNum int) bool {
	matches := e.patterns.CompiledNestController.FindStringSubmatch(line)
	if matches == nil {
		return false
	}
	if matches[1] != "" {
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   ensureLeadingSlash(matches[1]),
			File:   filePath,
			Line:   lineNum,
		})
	}
	return true
}

// handleCompiledNestMethod harvests the path of a compiled method decorator
// ((0, common_1.Get)(':id')) as a standalone route fragment. Bare decorators
// carry no path: the request is routed at the controller prefix, which is
// already harvested as its own fragment.
func (e *RouteExtractor) handleCompiledNestMethod(filePath, line string, lineNum int) bool {
	matches := e.patterns.CompiledNestMethod.FindStringSubmatch(line)
	if matches == nil {
		return false
	}
	if matches[2] != "" {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   ensureLeadingSlash(matches[2]),
			File:   filePath,
			Line:   lineNum,
		})
	}
	return true
}

func ensureLeadingSlash(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

// sortRouteFragments orders route fragments for the PartialRouteMatcher, which
// tries fragments in definition order: fewer parameter segments first (literal
// fragments must win over catch-alls), longer fragments next (more specific),
// then lexicographic for determinism.
func sortRouteFragments(fragments []string) {
	segments := func(f string) []string { return strings.Split(strings.Trim(f, "/"), "/") }
	params := func(f string) int {
		n := 0
		for _, s := range segments(f) {
			if strings.HasPrefix(s, ":") || (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) {
				n++
			}
		}
		return n
	}
	sort.Slice(fragments, func(i, j int) bool {
		pi, pj := params(fragments[i]), params(fragments[j])
		if pi != pj {
			return pi < pj
		}
		si, sj := len(segments(fragments[i])), len(segments(fragments[j]))
		if si != sj {
			return si > sj
		}
		return fragments[i] < fragments[j]
	})
}

func (e *RouteExtractor) handleHTTPDispatcher(filePath, line string, lineNum int) bool {
	if matches := e.patterns.HTTPDispatcher.FindStringSubmatch(line); len(matches) > 2 {
		method := strings.ToUpper(matches[1])
		// Extract path - either from string literal (group 2) or regex literal (group 3)
		path := matches[2]
		if path == "" && len(matches) > 3 {
			// It's a regex literal, wrap it to indicate regex
			path = "/" + matches[3] + "/"
		}
		e.routes = append(e.routes, RoutePattern{
			Method: method,
			Path:   path,
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}

	return false
}

func (e *RouteExtractor) handleFallback(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Fallback.FindStringSubmatch(line); len(matches) > 0 {
		e.routes = append(e.routes, RoutePattern{
			Method:  "ALL",
			Path:    matches[0],
			File:    filePath,
			Line:    lineNum,
			Handler: fallbackHandler,
		})
		return true
	}

	return false
}

// fallbackHandler marks routes guessed from arbitrary path-like string
// literals, as opposed to routes declared through a recognized framework API.
const fallbackHandler = "fallback"

// FrameworkRoutes returns the number of harvested routes that were declared
// through a recognized framework API (i.e. everything but fallback guesses).
func (e *RouteExtractor) FrameworkRoutes() int {
	n := 0
	for i := range e.routes {
		if e.routes[i].Handler != fallbackHandler {
			n++
		}
	}
	return n
}

// extractNextJSRoutesFromManifest tries to read a Next.js routes-manifest.json
// under the given directory. It adds any routes found to the extractor.
func (e *RouteExtractor) extractNextJSRoutesFromManifest(dir string) error {
	manifestPath := filepath.Join(dir, ".next", "routes-manifest.json")

	f, err := os.Open(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Not a Next.js app or no build output yet; nothing to do.
			return nil
		}
		return fmt.Errorf("open next.js routes-manifest %q: %w", manifestPath, err)
	}
	defer f.Close()

	var manifest nextRoutesManifest
	if err := json.NewDecoder(f).Decode(&manifest); err != nil {
		// Malformed JSON or incompatible format – return an error.
		return fmt.Errorf("decode next.js routes-manifest %q: %w", manifestPath, err)
	}

	// Convert Next.js params [id], [...slug] -> :id, :slug
	paramRe := regexp.MustCompile(`\[(\.\.\.)?([^\]]+)\]`)

	normalizePage := func(page string) string {
		return paramRe.ReplaceAllStringFunc(page, func(m string) string {
			sub := paramRe.FindStringSubmatch(m)
			if len(sub) < 3 {
				return m
			}
			// sub[1] is "..." or "", sub[2] is the param name
			name := sub[2]
			return ":" + name
		})
	}

	for _, r := range manifest.StaticRoutes {
		path := normalizePage(r.Page)
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   path,
			File:   manifestPath,
			Line:   0, // not line-based
		})
	}

	for _, r := range manifest.DynamicRoutes {
		path := normalizePage(r.Page)
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   path,
			File:   manifestPath,
			Line:   0,
		})
	}

	return nil
}

// ScanJSFileLines opens a JS/TS file and calls fn for each non-empty,
// non-comment line (trimmed). It skips non-regular files and files larger than
// MaxJSFileScanBytes. The callback receives the trimmed line and returns true
// to stop scanning early, or false to continue.
func ScanJSFileLines(path string, fn func(line string) bool) error {
	file, ok, err := openJSFileForScan(path)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer file.Close()

	inBlockComment := false
	scanner := bufio.NewScanner(io.LimitReader(file, MaxJSFileScanBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			continue
		}

		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "/*") {
			if !strings.Contains(line, "*/") {
				inBlockComment = true
			}
			continue
		}

		if fn(line) {
			return nil
		}
	}

	return scanner.Err()
}

func (e *RouteExtractor) scanFile(filePath string) error {
	file, ok, err := openJSFileForScan(filePath)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, MaxJSFileScanBytes))
	lineNum := 0
	var line string
	var save string

	// the NestJS controller prefix never spans files
	e.nestPrefix = ""

	for scanner.Scan() {
		lineNum++
		line = scanner.Text()
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.Contains(line, ";") {
			save = ""
		}
		if save != "" {
			line = save + "\n" + line
			save = ""
		}
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || trimmed == "" {
			continue
		}

		// Check for .route() pattern for chained handlers
		if e.expressPendingRoute(filePath, line, lineNum) {
			continue
		}

		// Express/Router, Koa, Fastify Short patterns
		if e.handleTypicalRoute(filePath, line, lineNum) {
			continue
		}

		// Fastify route object
		if e.handleFastifyRoute(filePath, line, lineNum) {
			continue
		}

		// Hapi
		if e.handleHapi(filePath, line, lineNum) {
			continue
		}

		// Restify
		if e.handleRestify(filePath, line, lineNum) {
			continue
		}

		if e.compiled {
			// NestJS decorators as lowered by tsc/swc, harvested as fragments
			if e.handleCompiledNestController(filePath, line, lineNum) {
				continue
			}
			if e.handleCompiledNestMethod(filePath, line, lineNum) {
				continue
			}
		} else {
			// NestJS @Controller() prefix, applied to the method decorators below it
			if e.handleNestJSController(line) {
				continue
			}

			// NestJS decorators
			if e.handleNestJS(filePath, line, lineNum) {
				continue
			}
		}

		// HttpDispatcher
		if e.handleHTTPDispatcher(filePath, line, lineNum) {
			continue
		}

		// Fallback when none matches. Compiled code is full of path-like string
		// literals, so no fallback guesses are harvested from it.
		if !e.compiled && e.handleFallback(filePath, line, lineNum) {
			continue
		}

		save = line
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (e *RouteExtractor) ScanDirectory(root string) error {
	walk := WalkJSFiles
	if e.compiled {
		walk = WalkCompiledJSFiles
	}
	return walk(root, func(path string) error {
		if err := e.scanFile(path); err != nil {
			e.log.Debug("error processing file", "file", path, "error", err)
		}
		return nil
	})
}

func (e *RouteExtractor) GetRoutes() []RoutePattern {
	return e.routes
}

// CleanupRegexPath converts regex route patterns to simplified path patterns
// with dynamic segments replaced by :id placeholder.
// Example: "/^\\/api\\/v1\\/products\\/[a-zA-Z0-9-]+$/" -> "/api/v1/products/:id"
func (e *RouteExtractor) CleanupRegexPath(path string) string {
	// If it's not a regex pattern (doesn't start /), return blank
	if !strings.HasPrefix(path, "/") || len(path) < 2 {
		return ""
	}

	// Remove the leading and trailing / markers
	pattern := path

	// Replace the typical regex patterns found in http dispatcher
	pattern = e.patterns.RegexPattern.ReplaceAllString(pattern, "")

	// Replace multiple consecutive slashes with a single slash
	pattern = e.patterns.MultipleSlashPattern.ReplaceAllString(pattern, "/")

	// Remove trailing slash
	if len(pattern) > 1 && strings.HasSuffix(pattern, "/") {
		pattern = pattern[:len(pattern)-1]
	}

	parts := strings.Split(pattern, "/")
	keep := make([]string, 0, len(parts))

	for i, p := range parts {
		p := strings.Trim(p, " ")
		if p == "" {
			continue
		}
		switch p[0] {
		case ':':
			p = ":" + e.patterns.CleanID.ReplaceAllString(parts[i], "")
			keep = append(keep, p)
			continue
		case '{':
			if p[len(p)-1] == '}' {
				p = "{" + e.patterns.CleanID.ReplaceAllString(parts[i], "") + "}"
				keep = append(keep, p)
				continue
			}
		case '[':
			if p[len(p)-1] == ']' {
				p = "[" + e.patterns.CleanID.ReplaceAllString(parts[i], "") + "]"
				keep = append(keep, p)
				continue
			}

		}

		qPos := strings.Index(p, "?")
		if qPos >= 0 {
			p = p[:qPos]
		}

		if !e.patterns.ValidPathChars.MatchString(p) {
			p = ":id"
		}

		keep = append(keep, p)
	}

	pattern = strings.Join(keep, "/")

	// Ensure the path starts with /
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	return pattern
}

func (e *RouteExtractor) GetHarvestedRoutes() []string {
	dedup := map[string]struct{}{}

	for _, r := range e.routes {
		route := e.CleanupRegexPath(r.Path)
		if route != "" && route != "/" {
			dedup[route] = struct{}{}
		}
	}

	result := make([]string, 0, len(dedup))
	for k := range dedup {
		result = append(result, k)
	}

	return result
}

func (e *RouteExtractor) FirstArg(args []string) string {
	return FirstArg(args)
}

// FirstArg returns the first non-flag argument from a Node.js command line,
// skipping flags (starting with '-') and the "inspect" keyword.
func FirstArg(args []string) string {
	for _, a := range args {
		if a == "" || a[0] == '-' || a == "inspect" {
			continue
		}
		return a
	}
	return ""
}

// testing
var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

// FindNodeJSAppDir locates the root directory of a Node.js application by
// reading its command line and working directory from /proc.
func FindNodeJSAppDir(pid app.PID) (string, error) {
	rootDir := rootDirForPID(pid)
	_, args, err := cmdlineForPID(pid)
	if err != nil {
		return "", fmt.Errorf("error finding cmd line: %w", err)
	}
	workdir, err := cwdForPID(pid)
	if err != nil {
		return "", fmt.Errorf("error finding cwd: %w", err)
	}

	firstArg := FirstArg(args)

	dir := FindScriptDirectory(rootDir, firstArg, workdir)
	if dir == "" {
		return "", fmt.Errorf("failed to find script directory for pid %d, script %s, cwd %s", pid, firstArg, workdir)
	}
	return dir, nil
}

// compiledSkipDirs is the skip list of the compiled-output scan: compiled
// JavaScript lives precisely in the directories the source scan skips.
var compiledSkipDirs = func() map[string]string {
	m := make(map[string]string, len(skipDirs))
	for k, v := range skipDirs {
		m[k] = v
	}
	delete(m, "dist")
	delete(m, "build")
	return m
}()

// WalkJSFiles walks a directory tree, skipping known non-application directories
// (node_modules, .git, system dirs, etc.), and calls fn for each regular JS/TS
// source file found (.js, .ts, .mjs, .cjs) that is not larger than
// MaxJSFileScanBytes. The callback can return filepath.SkipAll to stop the walk
// early.
func WalkJSFiles(root string, fn func(path string) error) error {
	return filepath.Walk(root, newJSFileWalker(root, skipDirs, false, fn))
}

// WalkCompiledJSFiles is WalkJSFiles for compiled output: it descends into
// compiled-output directories (dist, build) — including when root itself is
// one, as happens when the process entrypoint is an absolute path like
// /app/dist/main.js — so apps shipping only compiled code can be scanned.
func WalkCompiledJSFiles(root string, fn func(path string) error) error {
	return filepath.Walk(root, newJSFileWalker(root, compiledSkipDirs, true, fn))
}

func newJSFileWalker(root string, skip map[string]string, scanRoot bool, fn func(path string) error) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if scanRoot && path == root {
				return nil
			}
			name := info.Name()
			if name == "root" && path != root {
				return filepath.SkipDir
			}
			if _, ok := skip[name]; ok {
				return filepath.SkipDir
			}
			return nil
		}

		if !info.Mode().IsRegular() || info.Size() > MaxJSFileScanBytes {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".js" || ext == ".ts" || ext == ".mjs" || ext == ".cjs" {
			return fn(path)
		}

		return nil
	}
}

func ExtractNodejsRoutes(pid app.PID) (*RouteHarvesterResult, error) {
	dir, err := FindNodeJSAppDir(pid)
	if err != nil {
		return nil, err
	}

	jsExtractor := NewRouteExtractor()

	if err := jsExtractor.extractNextJSRoutesFromManifest(dir); err != nil {
		jsExtractor.log.Debug("error extracting next.js routes",
			"dir", dir,
			"error", err)
	}

	err = jsExtractor.ScanDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("error scanning directory, error %w", err)
	}

	// Routes declared through a recognized framework API are complete: prefix
	// and path are joined at harvest time and can be matched exactly.
	if jsExtractor.FrameworkRoutes() > 0 {
		return &RouteHarvesterResult{
			Routes: jsExtractor.GetHarvestedRoutes(),
			Kind:   CompleteRoutes,
		}, nil
	}

	// No framework routes in the sources: the app may ship only compiled
	// output (dist/, build/), which the source scan skips. Compiled decorators
	// lose the controller/method association, so their paths are harvested as
	// fragments and matched partially.
	compiledExtractor := NewCompiledRouteExtractor()
	if err := compiledExtractor.ScanDirectory(dir); err != nil {
		compiledExtractor.log.Debug("error scanning compiled output", "dir", dir, "error", err)
	}
	if fragments := compiledExtractor.GetHarvestedRoutes(); len(fragments) > 0 {
		sortRouteFragments(fragments)
		return &RouteHarvesterResult{
			Routes: fragments,
			Kind:   PartialRoutes,
		}, nil
	}

	// Neither sources nor compiled output declared routes: keep whatever the
	// fallback pattern guessed from the sources.
	return &RouteHarvesterResult{
		Routes: jsExtractor.GetHarvestedRoutes(),
		Kind:   CompleteRoutes,
	}, nil
}
