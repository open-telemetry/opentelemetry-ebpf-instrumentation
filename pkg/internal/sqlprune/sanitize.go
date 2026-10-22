// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune // import "go.opentelemetry.io/obi/pkg/internal/sqlprune"

import (
	"strings"

	"github.com/DataDog/go-sqllexer"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type sqlDialect struct {
	dbms                    sqllexer.DBMSType
	questionPlaceholders    bool
	dollarPlaceholders      bool
	namedDollarPlaceholders bool
}

var sqlppDialect = sqlDialect{
	dbms:                    sqllexer.DBMSMySQL,
	questionPlaceholders:    true,
	dollarPlaceholders:      true,
	namedDollarPlaceholders: true,
}

func dialectFor(kind request.SQLKind) sqlDialect {
	switch kind {
	case request.DBPostgres:
		return sqlDialect{dbms: sqllexer.DBMSPostgres, dollarPlaceholders: true}
	case request.DBMSSQL:
		return sqlDialect{dbms: sqllexer.DBMSSQLServer}
	case request.DBMySQL:
		return sqlDialect{dbms: sqllexer.DBMSMySQL, questionPlaceholders: true}
	default:
		return sqlDialect{dbms: sqllexer.DBMSPostgres, dollarPlaceholders: true}
	}
}

var obfuscator = sqllexer.NewObfuscator(
	sqllexer.WithReplaceDigits(false),
	sqllexer.WithDollarQuotedFunc(true),
	sqllexer.WithReplaceBoolean(true),
	sqllexer.WithReplaceNull(true),
)

func SanitizeSQL(query string, kind request.SQLKind) string {
	return sanitize(query, dialectFor(kind))
}

func SanitizeSQLPP(query string) string {
	return sanitize(query, sqlppDialect)
}

func sanitize(query string, d sqlDialect) string {
	tokens := tokenize(query, d)
	parameterized := hasPlaceholder(tokens, d)
	if parameterized && !hasStringLiteral(tokens) {
		return query
	}

	var out strings.Builder
	out.Grow(len(query))
	for i := range tokens {
		tok := &tokens[i]
		switch {
		case isUnterminatedDollarQuote(tok):
			out.WriteString(sqllexer.StringPlaceholder)
			continue
		case !parameterized || isStringLiteral(tok):
			obfuscator.ObfuscateTokenValue(tok, nil, sqllexer.WithDBMS(d.dbms))
		}
		out.WriteString(tok.Value)
	}
	return out.String()
}

func tokenize(query string, d sqlDialect) []sqllexer.Token {
	var tokens []sqllexer.Token
	offset := 0
	lexer := sqllexer.New(query, sqllexer.WithDBMS(d.dbms))
	for {
		tok := lexer.Scan()
		if tok.Type == sqllexer.EOF {
			return tokens
		}

		if d.namedDollarPlaceholders && offset >= 0 && isDollarToken(tok) {
			dollar := dollarToken(query[offset:])
			tokens = append(tokens, dollar)
			offset += len(dollar.Value)
			lexer = sqllexer.New(query[offset:], sqllexer.WithDBMS(d.dbms))
			continue
		}

		if offset >= 0 && strings.HasPrefix(query[offset:], tok.Value) {
			offset += len(tok.Value)
		} else {
			offset = -1
		}
		tokens = append(tokens, *tok)
	}
}

func isDollarToken(tok *sqllexer.Token) bool {
	return tok.Type != sqllexer.POSITIONAL_PARAMETER && strings.HasPrefix(tok.Value, "$")
}

func dollarToken(rest string) sqllexer.Token {
	end := len("$")
	for end < len(rest) && isNameChar(rest[end], end == len("$")) {
		end++
	}
	if end == len("$") {
		return sqllexer.Token{Type: sqllexer.UNKNOWN, Value: rest[:end]}
	}
	return sqllexer.Token{Type: sqllexer.BIND_PARAMETER, Value: rest[:end]}
}

func isNameChar(c byte, first bool) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || (!first && '0' <= c && c <= '9')
}

func hasPlaceholder(tokens []sqllexer.Token, d sqlDialect) bool {
	for i := range tokens {
		tok := &tokens[i]
		switch tok.Type {
		case sqllexer.POSITIONAL_PARAMETER:
			if d.dollarPlaceholders {
				return true
			}
		case sqllexer.BIND_PARAMETER:
			if !strings.HasPrefix(tok.Value, "@") {
				return true
			}
		case sqllexer.OPERATOR:
			if d.questionPlaceholders && strings.HasSuffix(tok.Value, "?") {
				return true
			}
			if isNamedColonParameter(tokens, i) {
				return true
			}
		}
	}
	return false
}

func isNamedColonParameter(tokens []sqllexer.Token, i int) bool {
	value := tokens[i].Value
	if !strings.HasSuffix(value, ":") || strings.HasSuffix(value, "::") || i+1 >= len(tokens) {
		return false
	}
	return tokens[i+1].Type == sqllexer.IDENT
}

func hasStringLiteral(tokens []sqllexer.Token) bool {
	for i := range tokens {
		if isStringLiteral(&tokens[i]) || isUnterminatedDollarQuote(&tokens[i]) {
			return true
		}
	}
	return false
}

func isStringLiteral(tok *sqllexer.Token) bool {
	switch tok.Type {
	case sqllexer.STRING, sqllexer.INCOMPLETE_STRING, sqllexer.DOLLAR_QUOTED_STRING, sqllexer.DOLLAR_QUOTED_FUNCTION:
		return true
	}
	return false
}

func isUnterminatedDollarQuote(tok *sqllexer.Token) bool {
	return tok.Type == sqllexer.ERROR && strings.HasPrefix(tok.Value, "$")
}
