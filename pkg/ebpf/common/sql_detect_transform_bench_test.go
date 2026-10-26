// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	benchmarkSQLIndex     int
	benchmarkSQLOp        string
	benchmarkSQLTables    []string
	benchmarkSQLStatement string
)

func BenchmarkASCIIIndexFold(b *testing.B) {
	type benchmarkCase struct {
		name   string
		input  string
		needle string
		want   int
	}

	tests := []benchmarkCase{
		{name: "empty", needle: "SELECT", want: -1},
		{name: "empty_needle", input: "SELECT", want: -1},
		{name: "short_invalid", input: "SELEC", needle: "SELECT", want: -1},
		{name: "upper_case", input: "SELECT * FROM accounts", needle: "SELECT", want: 0},
		{name: "mixed_case", input: "sElEcT * FROM accounts", needle: "SELECT", want: 0},
		{name: "partial_matches", input: strings.Repeat("SELECx", 512), needle: "SELECT", want: -1},
		{name: "binary_miss", input: strings.Repeat("\x00\x80\xff", 1024), needle: "SELECT", want: -1},
		{name: "first_match", input: "xx select SELECT", needle: "SELECT", want: 3},
	}

	for _, keyword := range []string{"SELECT", "UPDATE", "DELETE", "INSERT", "ALTER", "CREATE", "DROP", "EXECUTE "} {
		tests = append(tests, benchmarkCase{
			name:   "lower_case/" + strings.TrimSpace(keyword),
			input:  strings.ToLower(keyword) + " accounts",
			needle: keyword,
			want:   0,
		})
	}

	for _, offset := range []int{15, 31, 63} {
		tests = append(tests, benchmarkCase{
			name:   fmt.Sprintf("boundary/%d", offset),
			input:  strings.Repeat("x", offset) + "sElEcT",
			needle: "SELECT",
			want:   offset,
		})
	}

	const keyword = "sElEcT"
	for _, size := range []int{32, 256, 4096} {
		padding := strings.Repeat("x", size-len(keyword))
		middle := len(padding) / 2
		tests = append(tests,
			benchmarkCase{name: fmt.Sprintf("%dB/start", size), input: keyword + padding, needle: "SELECT", want: 0},
			benchmarkCase{name: fmt.Sprintf("%dB/middle", size), input: padding[:middle] + keyword + padding[middle:], needle: "SELECT", want: middle},
			benchmarkCase{name: fmt.Sprintf("%dB/end", size), input: padding + keyword, needle: "SELECT", want: len(padding)},
			benchmarkCase{name: fmt.Sprintf("%dB/miss", size), input: strings.Repeat("x", size), needle: "SELECT", want: -1},
		)
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			input, needle := []byte(tt.input), []byte(tt.needle)
			require.Equal(b, tt.want, asciiIndexFold(input, needle))

			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				benchmarkSQLIndex = asciiIndexFold(input, needle)
			}
		})
	}
}

func BenchmarkDetectSQL(b *testing.B) {
	const query = "SELECT * FROM accounts WHERE id = 42"
	longInsert := "INSERT INTO accounts (id) VALUES " + strings.Repeat("(1),", 1024) + "(2)"
	earlierUpdate := "UPDATE accounts SET note = 'SELECT * FROM orders' WHERE id = 42"

	tests := []qSQLTest{
		{name: "select", bytes: []byte(query), op: "SELECT", tables: []string{"accounts"}, sql: query},
		{name: "lower_case", bytes: []byte("select * from accounts"), op: "SELECT", tables: []string{"accounts"}, sql: "select * from accounts"},
		{name: "mixed_case", bytes: []byte("sElEcT * FrOm accounts"), op: "SELECT", tables: []string{"accounts"}, sql: "sElEcT * FrOm accounts"},
		{name: "update", bytes: []byte("UPDATE accounts SET balance = 1"), op: "UPDATE", tables: []string{"accounts"}, sql: "UPDATE accounts SET balance = 1"},
		{name: "insert", bytes: []byte("INSERT INTO accounts (id) VALUES (1)"), op: "INSERT", tables: []string{"accounts"}, sql: "INSERT INTO accounts (id) VALUES (1)"},
		{name: "delete", bytes: []byte("DELETE FROM accounts WHERE id = 42"), op: "DELETE", tables: []string{"accounts"}, sql: "DELETE FROM accounts WHERE id = 42"},
		{name: "alter", bytes: []byte("ALTER TABLE accounts ADD balance INT"), op: "ALTER", tables: []string{"accounts"}, sql: "ALTER TABLE accounts ADD balance INT"},
		{name: "create", bytes: []byte("CREATE TABLE accounts (id INT)"), op: "CREATE", tables: []string{"accounts"}, sql: "CREATE TABLE accounts (id INT)"},
		{name: "drop", bytes: []byte("DROP TABLE accounts"), op: "DROP", tables: []string{"accounts"}, sql: "DROP TABLE accounts"},
		{name: "long_insert", bytes: []byte(longInsert), op: "INSERT", tables: []string{"accounts"}, sql: longInsert},
		{name: "earliest_keyword", bytes: []byte(earlierUpdate), op: "UPDATE", tables: []string{"accounts"}, sql: earlierUpdate},
		{
			name:   "postgres_query",
			bytes:  postgresTestPacket(kPostgresQuery, append([]byte(query), 0)),
			op:     "SELECT",
			tables: []string{"accounts"},
			sql:    query,
		},
		{
			name:   "mysql_query",
			bytes:  mysqlPacket(kMySQLQuery, []byte(query)),
			op:     "SELECT",
			tables: []string{"accounts"},
			sql:    query,
		},
		{name: "empty"},
		{name: "short_invalid", bytes: []byte("SELECT")},
		{name: "binary_miss", bytes: []byte(strings.Repeat("\x00\x80\xff", 1024))},
		{name: "partial_matches", bytes: []byte(strings.Repeat("SELECx ", 512))},
	}

	for _, size := range []int{256, 4096} {
		tests = append(tests,
			qSQLTest{
				name:   fmt.Sprintf("%dB/late_match", size),
				bytes:  []byte(strings.Repeat("x", size-len(query)) + query),
				op:     "SELECT",
				tables: []string{"accounts"},
				sql:    query,
			},
			qSQLTest{
				name:  fmt.Sprintf("%dB/printable_miss", size),
				bytes: []byte(strings.Repeat("x", size)),
			},
		)
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			op, tables, sql := detectSQL(tt.bytes)
			require.Equal(b, tt.op, op)
			require.Equal(b, tt.tables, tables)
			require.Equal(b, tt.sql, sql)

			b.ReportAllocs()
			b.SetBytes(int64(len(tt.bytes)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				benchmarkSQLOp, benchmarkSQLTables, benchmarkSQLStatement = detectSQL(tt.bytes)
			}
		})
	}
}
