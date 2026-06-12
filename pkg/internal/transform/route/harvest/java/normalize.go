// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	curlyBracesRegexp = regexp.MustCompile(`\{([^}]*)\}`)
	validURLPath      = regexp.MustCompile(`^[A-Za-z0-9\-_{}\./]+$`)
	validParamName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func joinRoutePaths(classPath, methodPath string) string {
	classPath = strings.TrimSpace(classPath)
	methodPath = strings.TrimSpace(methodPath)

	if classPath == "" && methodPath == "" {
		return "/"
	}
	if classPath == "" {
		return ensureLeadingSlash(methodPath)
	}
	if methodPath == "" {
		return ensureLeadingSlash(classPath)
	}

	return "/" + strings.Trim(classPath, "/") + "/" + strings.Trim(methodPath, "/")
}

func normalizeRoute(route string) (string, bool) {
	route = strings.TrimSpace(route)
	if route == "" {
		return "", false
	}
	if strings.Contains(route, "*") ||
		strings.Contains(route, "?") ||
		strings.Contains(route, "#") ||
		strings.Contains(route, "://") ||
		strings.Contains(route, "${") {
		return "", false
	}

	route = ensureLeadingSlash(route)
	route = sanitizeParams(route)
	route = sanitizeColonParams(route)
	if len(route) > 1 {
		route = strings.TrimRight(route, "/")
	}

	if route == "/" {
		return route, true
	}
	if !validURLPath.MatchString(route) || !hasAlphanumeric(route) {
		return "", false
	}

	return route, true
}

func ensureLeadingSlash(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

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
		inside := match[1 : len(match)-1]
		var b strings.Builder
		for _, r := range inside {
			if (r == '_' && b.Len() == 0) ||
				(unicode.IsLetter(r) && b.Len() == 0) ||
				(b.Len() > 0 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_')) {
				b.WriteRune(r)
			} else {
				break
			}
		}
		return "{" + b.String() + "}"
	})
}

func sanitizeColonParams(s string) string {
	parts := strings.Split(s, "/")
	for i, part := range parts {
		if !strings.HasPrefix(part, ":") {
			continue
		}
		name := strings.TrimPrefix(part, ":")
		if !validParamName.MatchString(name) {
			continue
		}
		parts[i] = "{" + name + "}"
	}
	return strings.Join(parts, "/")
}
