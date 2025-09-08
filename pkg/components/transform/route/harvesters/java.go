package harvesters

import (
	"bufio"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/grafana/jvmtools/jvm"
)

type javaRouteHarvester struct {
	log *slog.Logger
}

const (
	jvmAnnotationDelimiter = ": /"
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

func (h *javaRouteHarvester) sortRoutes(routes []string) []string {
	sort.Slice(routes, func(i, j int) bool {
		hasParamsI := strings.Contains(routes[i], "{")
		hasParamsJ := strings.Contains(routes[j], "{")

		// If one has params and the other doesn't, non-param routes come first
		if hasParamsI && !hasParamsJ {
			return false
		}
		if !hasParamsI && hasParamsJ {
			return true
		}

		// If both have same param status, sort by length (longer first)
		return len(routes[i]) > len(routes[j])
	})

	return routes
}

func (h *javaRouteHarvester) ExtractRoutes(pid int32) (*RouteHarvesterResult, error) {
	routes := []string{}
	out, err := jvm.Jattach(int(pid), []string{"jcmd", "VM.symboltable -verbose"}, h.log)
	if err != nil {
		return nil, err
	}

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
		}
	}

	routes = h.sortRoutes(routes)

	h.log.Debug("java routes", "routes", routes)

	return &RouteHarvesterResult{Routes: routes, Kind: PartialRoutes}, nil
}
