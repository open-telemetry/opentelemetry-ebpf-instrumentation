// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRubyLines(t *testing.T) {
	t.Run("block comment lines are blanked", func(t *testing.T) {
		data := []byte("line1\n=begin\ninside comment\n=end\nafter\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{"line1", "", "", "", "after", ""}, result)
	})

	t.Run("=end with trailing text still closes the block comment", func(t *testing.T) {
		data := []byte("=begin\ncomment\n=end extra\nafter\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{"", "", "", "after", ""}, result)
	})

	t.Run("__END__ blanks every subsequent line including non-blank ones", func(t *testing.T) {
		data := []byte("before\n__END__\ndata line\nmore data\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{"before", "", "", "", ""}, result)
	})

	t.Run("carriage returns are stripped from ordinary output", func(t *testing.T) {
		data := []byte("puts 1\r\nputs 2\r\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{"puts 1", "puts 2", ""}, result)
	})

	t.Run("plain heredoc terminator must match exactly", func(t *testing.T) {
		data := []byte("EXAMPLE = <<DELIM\n  DELIM\nreal content\nDELIM\nafter\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{"EXAMPLE = <<DELIM", "", "", "", "after", ""}, result)
	})

	t.Run("dash heredoc allows an indented terminator", func(t *testing.T) {
		data := []byte("EXAMPLE = <<-DELIM\ncontent\n  DELIM\nafter\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{"EXAMPLE = <<-DELIM", "", "", "after", ""}, result)
	})

	t.Run("squiggly heredoc allows an indented terminator", func(t *testing.T) {
		data := []byte("EXAMPLE = <<~DELIM\n  content\n  DELIM\nafter\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{"EXAMPLE = <<~DELIM", "", "", "after", ""}, result)
	})

	t.Run("quoted heredoc delimiters", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			open string
		}{
			{name: "single quoted", open: "<<'ALPHA'"},
			{name: "double quoted", open: `<<"ALPHA"`},
		} {
			t.Run(tt.name, func(t *testing.T) {
				data := []byte("EXAMPLE = " + tt.open + "\ncontent\nALPHA\nafter\n")

				result := rubyLines(data, false)

				assert.Equal(t, []string{"EXAMPLE = " + tt.open, "", "", "after", ""}, result)
			})
		}
	})

	t.Run("two heredocs on one line close in the order they were opened", func(t *testing.T) {
		data := []byte("FIRST, SECOND = <<~ONE, <<~TWO\ncontent one\nONE\ncontent two\nTWO\nafter\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{
			"FIRST, SECOND = <<~ONE, <<~TWO",
			"",
			"",
			"",
			"",
			"after",
			"",
		}, result)
	})

	t.Run("a hash inside a string literal does not start a comment", func(t *testing.T) {
		data := []byte(`EXAMPLE = "text # not a comment"` + "\n")

		result := rubyLines(data, false)

		assert.Equal(t, []string{`EXAMPLE = "text # not a comment"`, ""}, result)
	})

	t.Run("eraseStrings toggles only the string-literal portion of the line", func(t *testing.T) {
		data := []byte(`EXAMPLE = "secret"` + "\n")

		preserved := rubyLines(data, false)
		erased := rubyLines(data, true)

		assert.Equal(t, `EXAMPLE = "secret"`, preserved[0])
		assert.Equal(t, "EXAMPLE = "+strings.Repeat(" ", len(`"secret"`)), erased[0])
		assert.NotEqual(t, preserved[0], erased[0])
	})
}

func TestMultilineRubySlashLiteral(t *testing.T) {
	t.Run("no slash on the line", func(t *testing.T) {
		literal, ok := multilineRubySlashLiteral("x = 1 + 2", 0)

		assert.False(t, ok)
		assert.Equal(t, rubySlashLiteral{}, literal)
	})

	t.Run("a hash before any slash starts a comment first", func(t *testing.T) {
		literal, ok := multilineRubySlashLiteral("# comment /regex/", 0)

		assert.False(t, ok)
		assert.Equal(t, rubySlashLiteral{}, literal)
	})

	t.Run("a slash literal that closes on the same line continues scanning and finds a later unclosed one", func(t *testing.T) {
		literal, ok := multilineRubySlashLiteral("x = /abc/; y = /unclosed", 0)

		assert.True(t, ok)
		assert.Equal(t, rubySlashLiteral{}, literal)
	})

	t.Run("a quote carried from a previous line hides a slash inside it", func(t *testing.T) {
		literal, ok := multilineRubySlashLiteral(`is a slash / here" x = /unclosed`, '"')

		assert.True(t, ok)
		assert.Equal(t, rubySlashLiteral{}, literal)
	})
}

func TestScanRubySlashLiteral(t *testing.T) {
	t.Run("a backslash escapes the next character so it cannot close the literal", func(t *testing.T) {
		literal, end, closed := scanRubySlashLiteral(`\/abc/`, 0, rubySlashLiteral{})

		assert.True(t, closed)
		assert.Equal(t, 5, end)
		assert.Equal(t, rubySlashLiteral{}, literal)
	})

	t.Run("a character class hides a slash and toggles back off", func(t *testing.T) {
		literal, end, closed := scanRubySlashLiteral(`[/]/`, 0, rubySlashLiteral{})

		assert.True(t, closed)
		assert.Equal(t, 3, end)
		assert.Equal(t, rubySlashLiteral{}, literal)
	})

	t.Run("an unterminated literal reaches the end of line", func(t *testing.T) {
		literal, end, closed := scanRubySlashLiteral("abc", 0, rubySlashLiteral{})

		assert.False(t, closed)
		assert.Equal(t, 3, end)
		assert.Equal(t, rubySlashLiteral{}, literal)
	})
}

func TestRubyRegexCanStart(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   bool
	}{
		{name: "empty prefix", prefix: "", want: true},
		{name: "whitespace-only prefix", prefix: "   ", want: true},
		{name: "ends with an operator character", prefix: "x =", want: true},
		{name: "ends with an opening paren", prefix: "foo(", want: true},
		{name: "keyword alone", prefix: "return", want: true},
		{name: "keyword preceded by a boundary", prefix: "foo; when", want: true},
		{name: "keyword as a suffix of a longer identifier", prefix: "myreturn", want: false},
		{name: "and as a suffix of a longer identifier", prefix: "brand", want: false},
		{name: "plain identifier", prefix: "x", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rubyRegexCanStart(tt.prefix))
		})
	}
}

func TestMultilineRubyPercentLiteral(t *testing.T) {
	t.Run("a closed percent literal is not multiline", func(t *testing.T) {
		literal, ok := multilineRubyPercentLiteral("data = %w[one two]", 0)

		assert.False(t, ok)
		assert.Equal(t, rubyPercentLiteral{}, literal)
	})

	t.Run("a hash before any percent starts a comment first", func(t *testing.T) {
		literal, ok := multilineRubyPercentLiteral("# comment %w[one", 0)

		assert.False(t, ok)
		assert.Equal(t, rubyPercentLiteral{}, literal)
	})

	t.Run("an unterminated percent literal is reported as multiline", func(t *testing.T) {
		literal, ok := multilineRubyPercentLiteral("data = %w[one two", 0)

		assert.True(t, ok)
		assert.Equal(t, rubyPercentLiteral{open: '[', close: ']', depth: 1}, literal)
	})

	t.Run("a backslash-escaped quote inside a string does not close it early", func(t *testing.T) {
		literal, ok := multilineRubyPercentLiteral(`consume "a\"b", %w(unterminated`, 0)

		assert.True(t, ok)
		assert.Equal(t, rubyPercentLiteral{open: '(', close: ')', depth: 1}, literal)
	})

	t.Run("a quote carried from a previous line hides a percent literal opener inside it", func(t *testing.T) {
		literal, ok := multilineRubyPercentLiteral(`still in string", %w[open`, '"')

		assert.True(t, ok)
		assert.Equal(t, rubyPercentLiteral{open: '[', close: ']', depth: 1}, literal)
	})

	t.Run("a modulo operator is rejected and scanning continues to a real percent literal", func(t *testing.T) {
		literal, ok := multilineRubyPercentLiteral("a % b + %w[open", 0)

		assert.True(t, ok)
		assert.Equal(t, rubyPercentLiteral{open: '[', close: ']', depth: 1}, literal)
	})
}

func TestRubyPercentLiteralAt(t *testing.T) {
	t.Run("rejections", func(t *testing.T) {
		tests := []struct {
			name  string
			line  string
			index int
		}{
			{name: "followed by a digit", line: "a %3", index: 2},
			{name: "followed by a space", line: "a % b", index: 2},
			{name: "followed by a tab", line: "a %\tb", index: 2},
			{name: "at end of line", line: "a %", index: 2},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				literal, next, ok := rubyPercentLiteralAt(tt.line, tt.index)

				assert.False(t, ok)
				assert.Equal(t, 0, next)
				assert.Equal(t, rubyPercentLiteral{}, literal)
			})
		}
	})

	t.Run("acceptances", func(t *testing.T) {
		t.Run("typed delimiter", func(t *testing.T) {
			literal, next, ok := rubyPercentLiteralAt("%w(items)", 0)

			assert.True(t, ok)
			assert.Equal(t, 3, next)
			assert.Equal(t, rubyPercentLiteral{open: '(', close: ')', depth: 1}, literal)
		})

		t.Run("bare delimiter without a type letter", func(t *testing.T) {
			literal, next, ok := rubyPercentLiteralAt("%(text)", 0)

			assert.True(t, ok)
			assert.Equal(t, 2, next)
			assert.Equal(t, rubyPercentLiteral{open: '(', close: ')', depth: 1}, literal)
		})

		t.Run("regex type letter", func(t *testing.T) {
			literal, next, ok := rubyPercentLiteralAt("%r{pattern}", 0)

			assert.True(t, ok)
			assert.Equal(t, 3, next)
			assert.Equal(t, rubyPercentLiteral{open: '{', close: '}', depth: 1}, literal)
		})
	})
}

func TestNewRubyPercentLiteral(t *testing.T) {
	tests := []struct {
		delimiter byte
		close     byte
	}{
		{delimiter: '(', close: ')'},
		{delimiter: '[', close: ']'},
		{delimiter: '{', close: '}'},
		{delimiter: '<', close: '>'},
		{delimiter: '|', close: '|'},
		{delimiter: '!', close: '!'},
	}

	for _, tt := range tests {
		t.Run(string(tt.delimiter), func(t *testing.T) {
			literal := newRubyPercentLiteral(tt.delimiter)

			assert.Equal(t, rubyPercentLiteral{open: tt.delimiter, close: tt.close, depth: 1}, literal)
		})
	}
}

func TestScanRubyPercentLiteral(t *testing.T) {
	t.Run("closing the literal drops the depth to zero", func(t *testing.T) {
		depth := scanRubyPercentLiteral("abc)", 0, rubyPercentLiteral{open: '(', close: ')', depth: 1})

		assert.Equal(t, 0, depth)
	})

	t.Run("an unterminated literal keeps its depth", func(t *testing.T) {
		depth := scanRubyPercentLiteral("abc", 0, rubyPercentLiteral{open: '(', close: ')', depth: 1})

		assert.Equal(t, 1, depth)
	})
}

func TestScanRubyPercentLiteralRange(t *testing.T) {
	t.Run("a nested paired delimiter increments depth so the first close does not end it", func(t *testing.T) {
		literal, end, closed := scanRubyPercentLiteralRange(
			" a (b) c )", 0, rubyPercentLiteral{open: '(', close: ')', depth: 1},
		)

		assert.True(t, closed)
		assert.Equal(t, 0, literal.depth)
		assert.Equal(t, len(" a (b) c )")-1, end)
	})

	t.Run("a backslash-escaped close delimiter is skipped rather than closing the literal", func(t *testing.T) {
		literal, end, closed := scanRubyPercentLiteralRange(
			`a\)b)`, 0, rubyPercentLiteral{open: '(', close: ')', depth: 1},
		)

		assert.True(t, closed)
		assert.Equal(t, 0, literal.depth)
		assert.Equal(t, 4, end)
	})

	t.Run("an unterminated literal reaches the end of line", func(t *testing.T) {
		literal, end, closed := scanRubyPercentLiteralRange(
			"abc", 0, rubyPercentLiteral{open: '(', close: ')', depth: 1},
		)

		assert.False(t, closed)
		assert.Equal(t, 1, literal.depth)
		assert.Equal(t, 3, end)
	})
}

func TestIsRubyWordByte(t *testing.T) {
	tests := []struct {
		value byte
		want  bool
	}{
		{value: 'A', want: true},
		{value: 'Z', want: true},
		{value: 'a', want: true},
		{value: 'z', want: true},
		{value: '0', want: true},
		{value: '9', want: true},
		{value: '_', want: true},
		{value: ' ', want: false},
		{value: '-', want: false},
		{value: '.', want: false},
		{value: '!', want: false},
	}

	for _, tt := range tests {
		t.Run(string(tt.value), func(t *testing.T) {
			assert.Equal(t, tt.want, isRubyWordByte(tt.value))
		})
	}
}

func TestRubyHeredocs(t *testing.T) {
	t.Run("no heredoc on the line", func(t *testing.T) {
		heredocs := rubyHeredocs("x = 1 + 2", 0)

		assert.Empty(t, heredocs)
	})

	t.Run("a plain heredoc opener", func(t *testing.T) {
		heredocs := rubyHeredocs("BODY = <<REAL", 0)

		assert.Equal(t, []rubyHeredoc{{delimiter: "REAL", allowIndent: false}}, heredocs)
	})

	t.Run("a closed percent literal masks an embedded heredoc-like marker", func(t *testing.T) {
		heredocs := rubyHeredocs("PATTERN = %w(<<FAKE) ; BODY = <<REAL", 0)

		assert.Equal(t, []rubyHeredoc{{delimiter: "REAL", allowIndent: false}}, heredocs)
	})

	t.Run("a closed slash literal masks an embedded heredoc-like marker", func(t *testing.T) {
		heredocs := rubyHeredocs("PATTERN = /<<FAKE/ ; BODY = <<REAL", 0)

		assert.Equal(t, []rubyHeredoc{{delimiter: "REAL", allowIndent: false}}, heredocs)
	})

	t.Run("an unterminated percent literal aborts scanning for the rest of the line", func(t *testing.T) {
		heredocs := rubyHeredocs("FIRST = <<ONE ; %w(unterminated <<TWO", 0)

		assert.Equal(t, []rubyHeredoc{{delimiter: "ONE", allowIndent: false}}, heredocs)
	})

	t.Run("an unterminated slash literal aborts scanning for the rest of the line", func(t *testing.T) {
		heredocs := rubyHeredocs("FIRST = <<ONE ; x = /unterminated <<TWO", 0)

		assert.Equal(t, []rubyHeredoc{{delimiter: "ONE", allowIndent: false}}, heredocs)
	})

	t.Run("a quoted heredoc delimiter that never reaches its closing quote is rejected", func(t *testing.T) {
		heredocs := rubyHeredocs("X = <<'DELIM", 0)

		assert.Empty(t, heredocs)
	})
}

func TestRubyHeredocCanStart(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   bool
	}{
		{name: "empty prefix", prefix: "", want: true},
		{name: "ends with an operator character", prefix: "BODY =", want: true},
		{name: "keyword alone", prefix: "return", want: true},
		{name: "keyword preceded by a boundary", prefix: "X and", want: true},
		{name: "keyword as a suffix of a longer identifier", prefix: "GRAND", want: false},
		{name: "known command call", prefix: "puts ", want: true},
		{name: "receiver command call", prefix: "logger.info ", want: true},
		{name: "ambiguous lowercase identifier fails closed as a heredoc", prefix: "items ", want: true},
		{name: "constant reference before a left shift", prefix: "VALUES ", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rubyHeredocCanStart(tt.prefix))
		})
	}
}

func TestCleanRubyLine(t *testing.T) {
	t.Run("a plain line is unchanged", func(t *testing.T) {
		preserved, erased, quote := cleanRubyLine("puts 1", 0)

		assert.Equal(t, "puts 1", preserved)
		assert.Equal(t, "puts 1", erased)
		assert.Equal(t, byte(0), quote)
	})

	t.Run("a comment truncates both preserved and erased output", func(t *testing.T) {
		preserved, erased, quote := cleanRubyLine("before # comment", 0)

		assert.Equal(t, "before ", preserved)
		assert.Equal(t, "before ", erased)
		assert.Equal(t, byte(0), quote)
	})

	t.Run("a quote carried over from a previous line blanks the preserved output entirely", func(t *testing.T) {
		preserved, erased, quote := cleanRubyLine(`closing" after`, '"')

		assert.Empty(t, preserved)
		assert.Equal(t, strings.Repeat(" ", len(`closing"`))+" after", erased)
		assert.Equal(t, byte(0), quote)
	})

	t.Run("a backslash inside a quote escapes the next character too", func(t *testing.T) {
		preserved, erased, quote := cleanRubyLine(`"a\"b"`, 0)

		assert.Equal(t, `"a\"b"`, preserved)
		assert.Equal(t, strings.Repeat(" ", len(`"a\"b"`)), erased)
		assert.Equal(t, byte(0), quote)
	})
}
