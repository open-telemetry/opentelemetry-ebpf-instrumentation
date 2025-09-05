package harvesters

import (
	"bufio"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/grafana/jvmtools/jvm"
)

type javaRouteHarvester struct {
	log *slog.Logger
}

const (
	jvmAnnotationDelimiter = " 1: /"
)

var validURLPath = regexp.MustCompile(`^[A-Za-z0-9\-._{}/]+$`)

func NewJavaRouteHarvester() *javaRouteHarvester {
	return &javaRouteHarvester{
		log: slog.With("component", "route.harvester.java"),
	}
}

func (h *javaRouteHarvester) ExtractRoutes(pid int32) ([]string, error) {
	routes := []string{}
	out, err := jvm.Jattach(int(pid), []string{"jcmd", "VM.symboltable -verbose"}, h.log)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		// output format is something like `17 1: /greeting123/{id}`
		if pos := strings.Index(line, jvmAnnotationDelimiter); pos > 0 {
			h.log.Debug("symbol", "line", line)
			start := pos + len(jvmAnnotationDelimiter)
			if start < len(line) {
				r := line[start-1:]
				if strings.HasPrefix(r, "/WEB-INF") || strings.HasPrefix(r, "/META-INF") || !validURLPath.MatchString(r) {
					continue
				}

				if u, err := url.ParseRequestURI(r); err == nil && u.Scheme == "" && u.Host == "" {
					routes = append(routes, r)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		h.log.Error("error reading from scanner", "error", err)
	}

	return routes, nil
}
