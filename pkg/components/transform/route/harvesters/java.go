package harvesters

import (
	"bufio"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/grafana/jvmtools/jvm"
)

type javaRouteHarvester struct {
	log *slog.Logger
}

const (
	jvmAnnotationDelimiter      = " 1: /"
	jvmAnnotationPartsDelimiter = " 2: /"
	jvmAnnotationRootDelimiter  = " 3: /"
)

var validURLPath = regexp.MustCompile(`^[A-Za-z0-9\-_{}/]+$`)

func NewJavaRouteHarvester() *javaRouteHarvester {
	return &javaRouteHarvester{
		log: slog.With("component", "route.harvester.java"),
	}
}

func (h *javaRouteHarvester) parseAndAdd(accumulator []string, line string, pos int, dLen int) []string {
	h.log.Debug("symbol", "line", line)

	start := pos + dLen
	if start < len(line) {
		r := line[start-1:]
		if strings.HasPrefix(r, "/WEB-INF") || strings.HasPrefix(r, "/META-INF") || !validURLPath.MatchString(r) || !hasAlphanumeric(r) {
			return accumulator
		}

		if u, err := url.ParseRequestURI(r); err == nil && u.Scheme == "" && u.Host == "" {
			accumulator = append(accumulator, r)
		}
	}

	return accumulator
}

var curlyBracesRegexp = regexp.MustCompile(`\{([^}]*)\}`)

func hasAlphanumeric(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func sanitizeParams(s string) string {
	return curlyBracesRegexp.ReplaceAllStringFunc(s, func(match string) string {
		// match is like "{id:\\d+}"
		inside := match[1 : len(match)-1]
		var b strings.Builder
		for _, r := range inside {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			} else {
				if b.Len() == 0 {
					return ""
				}
				break
			}
		}
		return "{" + b.String() + "}"
	})
}

func (h *javaRouteHarvester) ExtractRoutes(pid int32) ([]string, error) {
	routes := []string{}
	out, err := jvm.Jattach(int(pid), []string{"jcmd", "VM.symboltable -verbose"}, h.log)
	if err != nil {
		return nil, err
	}

	roots := []string{}

	parts := []string{}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		line = sanitizeParams(line)
		if len(line) == 0 {
			continue
		}

		// output format is something like `17 1: /greeting123/{id}`
		if pos := strings.Index(line, jvmAnnotationDelimiter); pos > 0 {
			routes = h.parseAndAdd(routes, line, pos, len(jvmAnnotationDelimiter))
		} else if pos := strings.Index(line, jvmAnnotationPartsDelimiter); pos > 0 {
			parts = h.parseAndAdd(parts, line, pos, len(jvmAnnotationPartsDelimiter))
		} else if pos := strings.Index(line, jvmAnnotationRootDelimiter); pos > 0 {
			roots = h.parseAndAdd(roots, line, pos, len(jvmAnnotationRootDelimiter))
		}
	}

	h.log.Debug("java routes", "routes", routes, "parts", parts, "roots", roots)

	if len(parts) > 0 {
		combined := Permutations2(parts)
		root := ""
		if len(roots) > 0 {
			root = roots[0]
		}

		partRoutes := []string{}

		for _, combination := range combined {
			if len(combination) > 0 {
				full := strings.Join(combination, "")
				if root != "" {
					full = root + full
				}
				partRoutes = append(partRoutes, full)
			}
		}

		for _, topR := range routes {
			for _, innerR := range partRoutes {
				routes = append(routes, topR+innerR)
			}
		}

		routes = append(routes, partRoutes...)
	} else if len(roots) > 0 {
		for _, root := range roots {
			routes = append(routes, root)
		}
	}

	if err := scanner.Err(); err != nil {
		h.log.Error("error reading from scanner", "error", err)
	}

	return routes, nil
}
