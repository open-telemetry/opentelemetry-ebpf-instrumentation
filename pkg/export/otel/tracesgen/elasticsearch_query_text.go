// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"strings"
	"unicode/utf8"
)

const (
	elasticsearchSanitizedValue = `"?"`
	elasticsearchBodySeparator  = ";"
	elasticsearchMaxDepth       = 10000
)

// sanitizeElasticsearchBody replaces every string, number, boolean and null in
// a JSON or NDJSON request body with "?", keeping field names and structure.
// It returns an empty string when the body is not valid JSON, so that no part
// of it is exported unsanitized.
func sanitizeElasticsearchBody(body string) string {
	if !utf8.ValidString(body) {
		return ""
	}

	// The first pass validates the body and measures the result, so that the
	// second pass makes a single allocation of the right size.
	sizer := esBodyScanner{body: body}
	if !sizer.scan() {
		return ""
	}

	var out strings.Builder
	out.Grow(sizer.size)
	writer := esBodyScanner{body: body, out: &out}
	writer.scan()
	return out.String()
}

// esBodyScanner only measures the size of the result when out is nil.
type esBodyScanner struct {
	body string
	pos  int
	out  *strings.Builder
	size int
}

func (s *esBodyScanner) scan() bool {
	for first := true; ; first = false {
		valueEnd := s.pos
		s.skipSpace()
		if s.pos == len(s.body) {
			return true
		}
		if !first {
			// NDJSON values must be on separate lines.
			if strings.IndexByte(s.body[valueEnd:s.pos], '\n') < 0 {
				return false
			}
			s.write(elasticsearchBodySeparator)
		}
		if !s.value(0) {
			return false
		}
	}
}

func (s *esBodyScanner) write(str string) {
	s.size += len(str)
	if s.out != nil {
		s.out.WriteString(str)
	}
}

func (s *esBodyScanner) writeByte(c byte) {
	s.size++
	if s.out != nil {
		s.out.WriteByte(c)
	}
}

func (s *esBodyScanner) value(depth int) bool {
	if s.pos == len(s.body) {
		return false
	}

	var ok bool
	switch c := s.body[s.pos]; {
	case c == '{':
		return s.object(depth + 1)
	case c == '[':
		return s.array(depth + 1)
	case c == '"':
		ok = s.skipString()
	case c == '-' || isDigit(c):
		ok = s.skipNumber()
	default:
		ok = s.skipLiteral("true") || s.skipLiteral("false") || s.skipLiteral("null")
	}
	if ok {
		s.write(elasticsearchSanitizedValue)
	}
	return ok
}

func (s *esBodyScanner) object(depth int) bool {
	if depth > elasticsearchMaxDepth {
		return false
	}
	s.pos++
	s.writeByte('{')
	s.skipSpace()
	if s.skipByte('}') {
		s.writeByte('}')
		return true
	}

	for {
		s.skipSpace()
		keyStart := s.pos
		if !s.skipString() {
			return false
		}
		s.write(s.body[keyStart:s.pos])

		s.skipSpace()
		if !s.skipByte(':') {
			return false
		}
		s.writeByte(':')

		s.skipSpace()
		if !s.value(depth) {
			return false
		}

		s.skipSpace()
		switch {
		case s.skipByte(','):
			s.writeByte(',')
		case s.skipByte('}'):
			s.writeByte('}')
			return true
		default:
			return false
		}
	}
}

func (s *esBodyScanner) array(depth int) bool {
	if depth > elasticsearchMaxDepth {
		return false
	}
	s.pos++
	s.writeByte('[')
	s.skipSpace()
	if s.skipByte(']') {
		s.writeByte(']')
		return true
	}

	for {
		s.skipSpace()
		if !s.value(depth) {
			return false
		}

		s.skipSpace()
		switch {
		case s.skipByte(','):
			s.writeByte(',')
		case s.skipByte(']'):
			s.writeByte(']')
			return true
		default:
			return false
		}
	}
}

func (s *esBodyScanner) skipString() bool {
	if !s.skipByte('"') {
		return false
	}
	for s.pos < len(s.body) {
		c := s.body[s.pos]
		s.pos++
		switch {
		case c == '"':
			return true
		case c < 0x20:
			return false
		case c == '\\':
			if s.pos == len(s.body) {
				return false
			}
			esc := s.body[s.pos]
			s.pos++
			switch esc {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				for range 4 {
					if s.pos == len(s.body) || !isHexDigit(s.body[s.pos]) {
						return false
					}
					s.pos++
				}
			default:
				return false
			}
		}
	}
	return false
}

func (s *esBodyScanner) skipNumber() bool {
	s.skipByte('-')
	switch {
	case s.skipByte('0'):
	case s.skipDigits():
	default:
		return false
	}
	if s.skipByte('.') && !s.skipDigits() {
		return false
	}
	if s.skipByte('e') || s.skipByte('E') {
		if !s.skipByte('+') {
			s.skipByte('-')
		}
		if !s.skipDigits() {
			return false
		}
	}
	return true
}

func (s *esBodyScanner) skipDigits() bool {
	start := s.pos
	for s.pos < len(s.body) && isDigit(s.body[s.pos]) {
		s.pos++
	}
	return s.pos > start
}

func (s *esBodyScanner) skipLiteral(lit string) bool {
	if !strings.HasPrefix(s.body[s.pos:], lit) {
		return false
	}
	s.pos += len(lit)
	return true
}

func (s *esBodyScanner) skipByte(c byte) bool {
	if s.pos < len(s.body) && s.body[s.pos] == c {
		s.pos++
		return true
	}
	return false
}

func (s *esBodyScanner) skipSpace() {
	for s.pos < len(s.body) {
		switch s.body[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

func isHexDigit(c byte) bool {
	return isDigit(c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}
