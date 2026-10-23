// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"strings"
	"testing"

	"github.com/DataDog/go-sqllexer"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type sanitizeCase struct {
	name     string
	kind     request.SQLKind
	query    string
	expected string
}

var sanitizeCases = []sanitizeCase{
	{"numeric comparison", request.DBPostgres, "SELECT count(*) >= 0 FROM conformance.items", "SELECT count(*) >= ? FROM conformance.items"},
	{"insert values", request.DBMySQL, "INSERT INTO t (id, name) VALUES (1, 'first')", "INSERT INTO t (id, name) VALUES (?, ?)"},
	{"negative number", request.DBMySQL, "SELECT * FROM t WHERE id = -1", "SELECT * FROM t WHERE id = ?"},
	{"negative numbers in list", request.DBMySQL, "SELECT * FROM t WHERE id IN (-1, 2, +3)", "SELECT * FROM t WHERE id IN (?, ?, ?)"},
	{"binary minus", request.DBMySQL, "SELECT a - 1, a-1, (a)-2 FROM t", "SELECT a - ?, a?, (a)? FROM t"},
	{"minus after binary minus", request.DBMySQL, "SELECT a - -1 FROM t", "SELECT a - ? FROM t"},
	{"leading negative", request.DBMySQL, "SELECT -1", "SELECT ?"},
	{"postgres placeholders", request.DBPostgres, "SELECT * FROM users WHERE id = $1 AND name = $2", "SELECT * FROM users WHERE id = $1 AND name = $2"},
	{"mysql placeholders", request.DBMySQL, "SELECT * FROM users WHERE id = ? AND name = ?", "SELECT * FROM users WHERE id = ? AND name = ?"},
	{"named placeholders", request.DBGeneric, "SELECT * FROM users WHERE id = :id AND name = @p1", "SELECT * FROM users WHERE id = :id AND name = @p1"},
	{"postgres cast", request.DBPostgres, "SELECT a::int + 2 FROM t", "SELECT a::int + ? FROM t"},
	{"postgres parameterized with literal", request.DBPostgres, "SELECT * FROM t WHERE id = $1 LIMIT 10", "SELECT * FROM t WHERE id = $1 LIMIT 10"},
	{"mysql parameterized with string", request.DBMySQL, "SELECT * FROM t WHERE a = ? AND b = 'x' LIMIT 10", "SELECT * FROM t WHERE a = ? AND b = ? LIMIT 10"},
	{"postgres parameterized with string", request.DBPostgres, "SELECT * FROM t WHERE id = $1 AND name = 'bob' LIMIT 10", "SELECT * FROM t WHERE id = $1 AND name = ? LIMIT 10"},
	{"postgres parameterized with dollar quote", request.DBPostgres, "SELECT $$secret$$ FROM t WHERE id = $1", "SELECT ? FROM t WHERE id = $1"},
	{"mssql at variable is not a parameter", request.DBMSSQL, "SELECT TOP 5 * FROM t WHERE a = @p1 AND b = N'x'", "SELECT TOP ? * FROM t WHERE a = @p1 AND b = N?"},
	{"mssql declare", request.DBMSSQL, "DECLARE @x INT = 5; SELECT * FROM users WHERE ssn = '123-45-6789'", "DECLARE @x INT = ?; SELECT * FROM users WHERE ssn = ?"},
	{"mssql set variable", request.DBMSSQL, "SET @a = 1", "SET @a = ?"},
	{"generic set variable", request.DBGeneric, "SET @a = 1", "SET @a = ?"},
	{"generic question operator", request.DBGeneric, "SELECT * FROM t WHERE data ? 'k' AND id = 1", "SELECT * FROM t WHERE data ? ? AND id = ?"},
	{"postgres question operator after parameter", request.DBPostgres, "SELECT * FROM t WHERE id = $1 AND data ? 'k'", "SELECT * FROM t WHERE id = $1 AND data ? ?"},
	{"named parameter with literal", request.DBPostgres, "SELECT * FROM t WHERE a = :id AND b = 1", "SELECT * FROM t WHERE a = :id AND b = 1"},
	{"generic dollar parameter", request.DBGeneric, "SELECT * FROM t WHERE a = $2 AND b = 1", "SELECT * FROM t WHERE a = $2 AND b = 1"},
	{"question mark in string is not a parameter", request.DBMySQL, "SELECT * FROM t WHERE a = '?' AND b = 1", "SELECT * FROM t WHERE a = ? AND b = ?"},
	{"question mark in comment is not a parameter", request.DBMySQL, "SELECT 1 /* ? */", "SELECT ? /* ? */"},
	{"postgres question operator", request.DBPostgres, "SELECT * FROM t WHERE data ? 'k'", "SELECT * FROM t WHERE data ? ?"},
	{"mysql user variable", request.DBMySQL, "SET @a = 1", "SET @a = ?"},
	{"mssql system variable", request.DBMSSQL, "SELECT @@ROWCOUNT + 1", "SELECT @@ROWCOUNT + ?"},
	{"mysql dollar is not a parameter", request.DBMySQL, "SELECT $1, 2", "SELECT $1, ?"},
	{"line comment", request.DBMySQL, "SELECT 1 -- it's 2\nFROM t", "SELECT ? -- it's 2\nFROM t"},
	{"block comment", request.DBPostgres, "SELECT /* id = 5 */ a FROM t WHERE b = 7", "SELECT /* id = 5 */ a FROM t WHERE b = ?"},
	{"hash comment", request.DBMySQL, "SELECT a FROM t # where 'x'\nWHERE b = 7", "SELECT a FROM t # where 'x'\nWHERE b = ?"},
	{"mysql executable comment", request.DBMySQL, "SELECT /*!40001 SQL_NO_CACHE */ a FROM t WHERE b = 'x'", "SELECT /*!40001 SQL_NO_CACHE */ a FROM t WHERE b = ?"},
	{"postgres hash operator", request.DBPostgres, "SELECT a # 5 FROM t", "SELECT a # ? FROM t"},
	{"mssql temp table", request.DBMSSQL, "SELECT * FROM #tmp WHERE id = 1", "SELECT * FROM #tmp WHERE id = ?"},
	{"postgres quoted identifier", request.DBPostgres, `SELECT "a", "Col 1" FROM "Users" WHERE "id" = 1`, `SELECT "a", "Col 1" FROM "Users" WHERE "id" = ?`},
	{"mysql double quoted string", request.DBMySQL, `SELECT * FROM t WHERE name = "bob"`, `SELECT * FROM t WHERE name = ?`},
	{"backtick identifier", request.DBMySQL, "SELECT `a`, `col 1` FROM `t1` WHERE `x` = 'y'", "SELECT `a`, `col 1` FROM `t1` WHERE `x` = ?"},
	{"mssql bracket identifier", request.DBMSSQL, "SELECT [col 1] FROM [dbo].[t2] WHERE id = 3", "SELECT [col 1] FROM [dbo].[t2] WHERE id = ?"},
	{"mssql unicode string", request.DBMSSQL, "SELECT * FROM t WHERE name = N'Jos''e'", "SELECT * FROM t WHERE name = N?"},
	{"doubled quote escape", request.DBPostgres, "SELECT * FROM t WHERE a = 'it''s' AND b = 2", "SELECT * FROM t WHERE a = ? AND b = ?"},
	{"backslash escape mysql", request.DBMySQL, `SELECT * FROM t WHERE a = 'it\'s' AND b = 'c'`, `SELECT * FROM t WHERE a = ? AND b = ?`},
	{"postgres standard string backslash", request.DBPostgres, `INSERT INTO t VALUES ('C:\', 'secret')`, `INSERT INTO t VALUES (?, ?)`},
	{"postgres escape string", request.DBPostgres, `SELECT E'it\'s', e'a\nb' FROM t`, `SELECT E?, e? FROM t`},
	{"postgres unicode string", request.DBPostgres, `SELECT U&'d\0061t' FROM t`, `SELECT U&? FROM t`},
	{"dollar quoted", request.DBPostgres, "SELECT $$it's secret$$, $fn$body $$ x$fn$ FROM t", "SELECT ?, ? FROM t"},
	{"unterminated dollar quote", request.DBPostgres, "SELECT $$it's sec", "SELECT ?"},
	{"lone dollar", request.DBMSSQL, "SELECT $action FROM t", "SELECT $action FROM t"},
	{"identifier with dollar", request.DBMySQL, "SELECT a$1 FROM t", "SELECT a$1 FROM t"},
	{"hex and bit literals", request.DBMySQL, "SELECT X'1F', x'ab', 0x1F, b'101', B'1' FROM t", "SELECT X?, x?, ?, b?, B? FROM t"},
	{"charset introducer", request.DBMySQL, "SELECT _utf8mb4'abc' FROM t", "SELECT _utf8mb4? FROM t"},
	{"booleans", request.DBPostgres, "UPDATE t SET active = TRUE WHERE deleted = false", "UPDATE t SET active = ? WHERE deleted = ?"},
	{"null replaced", request.DBPostgres, "SELECT * FROM t WHERE a IS NULL", "SELECT * FROM t WHERE a IS ?"},
	{"limit offset", request.DBPostgres, "SELECT * FROM t ORDER BY id LIMIT 10 OFFSET 20", "SELECT * FROM t ORDER BY id LIMIT ? OFFSET ?"},
	{"mysql limit pair", request.DBMySQL, "SELECT * FROM t LIMIT 5, 10", "SELECT * FROM t LIMIT ?, ?"},
	{"digits in identifiers", request.DBMySQL, "SELECT t1.col_2, x3 FROM t1 JOIN t22 ON t1.id = t22.id", "SELECT t1.col_2, x3 FROM t1 JOIN t22 ON t1.id = t22.id"},
	{"scientific notation", request.DBMySQL, "SELECT 1.5e10, 2E-3, .5, 3. FROM t", "SELECT ?, ?, .?, ? FROM t"},
	{"call procedure", request.DBMySQL, "CALL proc(1,'x')", "CALL proc(?,?)"},
	{"date and interval", request.DBPostgres, "SELECT DATE '2024-01-01' + INTERVAL '1 day'", "SELECT DATE ? + INTERVAL ?"},
	{"truncated string", request.DBMySQL, "INSERT INTO t VALUES (1, 'secr", "INSERT INTO t VALUES (?, ?"},
	{"truncated identifier", request.DBPostgres, `SELECT "Us`, `SELECT "Us`},
	{"truncated comment", request.DBPostgres, "SELECT 1 /* 2", "SELECT ? /* 2"},
	{"truncated number", request.DBMySQL, "SELECT * FROM t WHERE id = 12", "SELECT * FROM t WHERE id = ?"},
	{"truncated escape", request.DBMySQL, `SELECT 'abc\`, `SELECT ?`},
	{"whitespace preserved", request.DBMySQL, "SELECT\n\ta\nFROM  t\r\nWHERE b =\t'x'", "SELECT\n\ta\nFROM  t\r\nWHERE b =\t?"},
	{"non ascii identifier", request.DBPostgres, "SELECT naïve1, ü2 FROM t WHERE x = 'é'", "SELECT naïve1, ü2 FROM t WHERE x = ?"},
	{"multiple statements", request.DBMySQL, "SET a = 1; SELECT -2", "SET a = ?; SELECT ?"},
	{"generic double quoted identifiers", request.DBGeneric, `SELECT "id" FROM "users" WHERE "a" = 1`, `SELECT ? FROM ? WHERE ? = ?`},
	{"generic backslash before closing quote is omitted", request.DBGeneric, `INSERT INTO t VALUES ('C:\', 'secret')`, ""},
	{"generic doubled quote escape", request.DBGeneric, "SELECT 'it''s', 2", "SELECT ?, ?"},
	{"generic hash is not a comment", request.DBGeneric, "SELECT a FROM t # 'x'", "SELECT a FROM t # ?"},
	{"postgres json path", request.DBPostgres, "SELECT data->>'name' FROM t WHERE id = 7", "SELECT data->>? FROM t WHERE id = ?"},
	{"dollar quoted function", request.DBPostgres, "CREATE FUNCTION f() RETURNS int AS $func$ SELECT 1 $func$ LANGUAGE sql", "CREATE FUNCTION f() RETURNS int AS ? LANGUAGE sql"},
	{"postgres func tag is an ordinary dollar quote", request.DBPostgres, "SELECT $func$secret$func$ FROM users", "SELECT ? FROM users"},
	{"mysql dashes without space are not a comment", request.DBMySQL, "SELECT 1--1, 'secret' FROM users", "SELECT ?-?, ? FROM users"},
	{"mysql dashes followed by control character", request.DBMySQL, "SELECT 1 --\t'x'\nFROM t", "SELECT ? --\t'x'\nFROM t"},
	{"mysql compacted identifier before dashes", request.DBMySQL, "SELECT `a` . `b` --1, 'secret'", "SELECT `a`.`b` -?, ?"},
	{"mysql binary number", request.DBMySQL, "SELECT 0b101010, 0B1 FROM t", "SELECT ?, ? FROM t"},
	{"postgres non decimal and underscored numbers", request.DBPostgres, "SELECT 0b101, 0o17, 1_000_000, 0x1F_FF FROM t", "SELECT ?, ?, ?, ? FROM t"},
	{"postgres bit and hex strings", request.DBPostgres, "SELECT X'1F', B'101' FROM t", "SELECT X?, B? FROM t"},
	{"postgres escape string with escaped quote", request.DBPostgres, `SELECT E'\'secret' FROM t`, `SELECT E? FROM t`},
	{"postgres array slice is not a placeholder", request.DBPostgres, "SELECT items[1:upper_bound] FROM users WHERE ssn=123456789", "SELECT items[?:upper_bound] FROM users WHERE ssn=?"},
	{"postgres nested comment", request.DBPostgres, "SELECT /* a /* b */ 'secret' */ 1", "SELECT /* a /* b */ ? */ ?"},
	{"mysql executable comment literal", request.DBMySQL, "SELECT /*!40001 'secret' */ a FROM t WHERE b = 1", "SELECT /*!40001 ? */ a FROM t WHERE b = ?"},
	{"mariadb executable comment literal", request.DBMySQL, "SELECT /*M!100100 'secret' */ 1", "SELECT /*M!100100 ? */ ?"},
	{"mysql optimizer hint literal", request.DBMySQL, "SELECT /*+ SET_VAR(x='secret') */ a FROM t", "SELECT /*+ SET_VAR(x=?) */ a FROM t"},
	{"truncated executable comment", request.DBMySQL, "SELECT /*! 'secret'", "SELECT /*! ?"},
	{"generic double quoted string", request.DBGeneric, `SELECT * FROM students WHERE name = "secret"`, `SELECT * FROM students WHERE name = ?`},
	{"generic double quoted string with placeholder", request.DBGeneric, `SELECT * FROM t WHERE a = $1 AND b = "secret" LIMIT 5`, `SELECT * FROM t WHERE a = $1 AND b = ? LIMIT 5`},
	{"generic truncated double quote", request.DBGeneric, `SELECT "secr`, `SELECT ?`},
	{"generic escape string is omitted", request.DBGeneric, `SELECT e'\', 'secret'`, ""},
	{"generic oracle quote is omitted", request.DBGeneric, `SELECT q'[it's secret]' FROM dual`, ""},
	{"generic backslash without quote", request.DBGeneric, `SELECT 'C:\path' FROM t`, `SELECT ? FROM t`},
	{"mssql double quoted string", request.DBMSSQL, `SELECT * FROM t WHERE name = "secret"`, `SELECT * FROM t WHERE name = ?`},
	{"mssql money literal", request.DBMSSQL, "SELECT * FROM t WHERE price = $12.50", "SELECT * FROM t WHERE price = ?.?"},
	{"empty", request.DBMySQL, "", ""},
	{"nul byte ends the statement", request.DBMySQL, "SELECT 1\x00 'secret'", "SELECT ?"},
}

var sqlppCases = []struct {
	name     string
	query    string
	expected string
}{
	{"literals", "SELECT * FROM `travel-sample` WHERE type = \"airline\" AND id = 10 LIMIT 5", "SELECT * FROM `travel-sample` WHERE type = ? AND id = ? LIMIT ?"},
	{"backslash escape", `SELECT * FROM b WHERE a = "x\"y" AND c = 'it\'s'`, `SELECT * FROM b WHERE a = ? AND c = ?`},
	{"named parameter", "SELECT * FROM b WHERE type = $type AND id = 10", "SELECT * FROM b WHERE type = $type AND id = 10"},
	{"named parameter with string", `SELECT * FROM b WHERE type = $type AND name = "x" LIMIT 5`, `SELECT * FROM b WHERE type = $type AND name = ? LIMIT 5`},
	{"positional parameters", "SELECT * FROM b WHERE a = $1 AND c = ? LIMIT 5", "SELECT * FROM b WHERE a = $1 AND c = ? LIMIT 5"},
	{"lone dollar", "SELECT $ FROM b WHERE a = 1", "SELECT $ FROM b WHERE a = ?"},
	{"hash is not a comment", "SELECT * FROM b WHERE a = 1 # 'secret'", "SELECT * FROM b WHERE a = ? # ?"},
	{"named parameters around string", `SELECT * FROM b WHERE a = $x AND c = "$y" AND d = $z`, `SELECT * FROM b WHERE a = $x AND c = ? AND d = $z`},
}

func TestSanitizeSQLPP(t *testing.T) {
	for _, tc := range sqlppCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SanitizeSQLPP(tc.query))
		})
	}
}

func TestSanitizeSQL(t *testing.T) {
	for _, tc := range sanitizeCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SanitizeSQL(tc.query, tc.kind))
		})
	}
}

func TestSanitizeSQLTruncatedInputs(t *testing.T) {
	kinds := []request.SQLKind{request.DBGeneric, request.DBPostgres, request.DBMySQL, request.DBMSSQL}
	for _, tc := range sanitizeCases {
		for cut := range len(tc.query) {
			for _, kind := range kinds {
				assert.NotPanics(t, func() { SanitizeSQL(tc.query[:cut], kind) })
			}
		}
	}
}

func TestSanitizeSQLParameterizedUnchanged(t *testing.T) {
	queries := map[request.SQLKind]string{
		request.DBPostgres: `SELECT "u"."id", t1.name FROM "users" "u" JOIN t1 ON t1.id = "u"."id" WHERE "u"."id" = $1 OR t1.x IN ($2, $3)`,
		request.DBMySQL:    "INSERT INTO `t` (`a`, b2) VALUES (?, ?) ON DUPLICATE KEY UPDATE b2 = ?",
		request.DBMSSQL:    "SELECT TOP (@p1) [id] FROM [dbo].[orders] WHERE [customer] = @p2",
	}
	for kind, query := range queries {
		assert.Equal(t, query, SanitizeSQL(query, kind))
	}
}

func TestHasLiteral(t *testing.T) {
	assert.False(t, hasLiteral("SELECT ? FROM t", dialectFor(request.DBMySQL)))
	assert.True(t, hasLiteral("SELECT 'x' FROM t", dialectFor(request.DBMySQL)))
	assert.True(t, hasLiteral("SELECT $$x$$ FROM t", dialectFor(request.DBPostgres)))
	assert.False(t, hasLiteral(`SELECT "x" FROM t`, dialectFor(request.DBPostgres)))
	assert.True(t, hasLiteral(`SELECT "x" FROM t`, dialectFor(request.DBGeneric)))
}

func FuzzSanitizeSQL(f *testing.F) {
	for _, tc := range sanitizeCases {
		f.Add("s3cr3t", tc.query, uint8(tc.kind))
	}
	for _, tc := range sqlppCases {
		f.Add("s3cr3t", tc.query, uint8(len(fuzzDialects)-1))
	}

	f.Fuzz(func(t *testing.T, secret, suffix string, dialect uint8) {
		const prefix = "SELECT "
		if len(secret) < 3 || strings.ContainsAny(secret, "'\"?") ||
			strings.Contains(prefix, secret) || strings.Contains(" "+suffix, secret) {
			return
		}

		d := fuzzDialects[int(dialect)%len(fuzzDialects)]
		quotes := []string{"'"}
		if d.doubleQuotedStrings || d.dbms == sqllexer.DBMSMySQL {
			quotes = append(quotes, `"`)
		}
		for _, quote := range quotes {
			got := sanitize(prefix+quote+secret+quote+" "+suffix, d)
			assert.NotContains(t, got, secret)
		}
	})
}

var fuzzDialects = []sqlDialect{
	dialectFor(request.DBGeneric),
	dialectFor(request.DBPostgres),
	dialectFor(request.DBMySQL),
	dialectFor(request.DBMSSQL),
	sqlppDialect,
}
