// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type bindParseResult struct {
	statement    string
	portal       string
	args         []string
	hasErr       bool
	hasASCIIArgs bool
}

type bindTest struct {
	name   string
	bytes  []byte
	isBind bool
	result bindParseResult
}

func TestPostgresBindParsing(t *testing.T) {
	for _, ts := range []bindTest{
		{
			name:   "Valid bind",
			bytes:  []byte{66, 0, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "ecto_1158",
				args:         []string{"recommendationCache"},
				hasErr:       false,
				hasASCIIArgs: true,
			},
		},
		{
			name:   "Less length than needed",
			bytes:  []byte{66, 0, 0, 0, 12, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "",
				args:         nil,
				hasErr:       true,
				hasASCIIArgs: true,
			},
		},
		{
			name:   "Not a bind",
			bytes:  []byte{67, 0, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "Too long",
			bytes:  []byte{66, 100, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "Too short",
			bytes:  []byte{67, 100},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "Empty",
			bytes:  []byte{},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "A bind, but without anything reasonable",
			bytes:  []byte{66, 0, 0, 0, 12},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "",
				args:         nil,
				hasErr:       true,
				hasASCIIArgs: true,
			},
		},
		{
			name:   "Crazy long argument length",
			bytes:  []byte{66, 0, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 100, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "ecto_1158",
				args:         []string{"recommendationCache"},
				hasErr:       false,
				hasASCIIArgs: false,
			},
		},
	} {
		t.Run(ts.name, func(t *testing.T) {
			lb := largebuf.NewLargeBufferFrom(ts.bytes)
			ok := isPostgresBindCommand(lb)
			assert.Equal(t, ts.isBind, ok)
			if ok {
				statement, portal, args, err := parsePostgresBindCommand(lb)
				if ts.result.hasErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, ts.result.statement, statement)
				assert.Equal(t, ts.result.portal, portal)
				if ts.result.hasASCIIArgs {
					assert.Equal(t, ts.result.args, args)
				} else {
					for _, arg := range args {
						assert.False(t, isASCII(arg))
					}
				}
			}
		})
	}
}

type qSQLTest struct {
	name   string
	bytes  []byte
	op     string
	tables []string
	sql    string
}

func TestPostgresQueryParsing(t *testing.T) {
	for _, ts := range []qSQLTest{
		{
			name:   "Query with insert and update as keywords",
			bytes:  []byte{166, 0, 0, 0, 3, 73, 78, 83, 69, 82, 84, 32, 73, 78, 84, 79, 32, 96, 117, 115, 101, 114, 115, 96, 32, 40, 96, 110, 97, 109, 101, 96, 44, 32, 96, 101, 109, 97, 105, 108, 96, 44, 32, 96, 99, 114, 101, 97, 116, 101, 100, 95, 97, 116, 96, 44, 32, 96, 117, 112, 100, 97, 116, 101, 100, 95, 97, 116, 96, 41, 32, 86, 65, 76, 85, 69, 83, 32, 40, 39, 74, 111, 104, 110, 32, 68, 111, 101, 39, 44, 32, 39, 106, 111, 104, 110, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 39, 44, 32, 39, 50, 48, 50, 53, 45, 49, 50, 45, 48, 52, 32, 49, 55, 58, 50, 54, 58, 52, 54, 46, 56, 56, 52, 57, 54, 56, 39, 44, 32, 39, 50, 48, 50, 53, 45, 49, 50, 45, 48, 52, 32, 49, 55, 58, 50, 54, 58, 52, 54, 46, 56, 56, 52, 57, 54, 56, 39, 41},
			op:     "INSERT",
			tables: []string{"users"},
			sql:    "INSERT INTO `users` (`name`, `email`, `created_at`, `updated_at`) VALUES ('John Doe', 'john@example.com', '2025-12-04 17:26:46.884968', '2025-12-04 17:26:46.884968')",
		},
		{
			name:   "Query with expanded field names",
			bytes:  []byte{81, 0, 0, 3, 114, 83, 69, 76, 69, 67, 84, 32, 68, 73, 83, 84, 73, 78, 67, 84, 32, 34, 97, 117, 116, 104, 95, 112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 34, 46, 34, 105, 100, 34, 44, 32, 34, 100, 106, 97, 110, 103, 111, 95, 99, 111, 110, 116, 101, 110, 116, 95, 116, 121, 112, 101, 34, 46, 34, 97, 112, 112, 95, 108, 97, 98, 101, 108, 34, 44, 32, 34, 100, 106, 97, 110, 103, 111, 95, 99, 111, 110, 116, 101, 110, 116, 95, 116, 121, 112, 101, 34, 46, 34, 109, 111, 100, 101, 108, 34, 44, 32, 34, 97, 117, 116, 104, 95, 112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 34, 46, 34, 99, 111, 100, 101, 110, 97, 109, 101, 34, 32, 70, 82, 79, 77, 32, 34, 97, 117, 116, 104, 95, 112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 34, 32, 76, 69, 70, 84, 32, 79, 85, 84, 69, 82, 32, 74, 79, 73, 78, 32, 34, 97, 117, 116, 104, 95, 117, 115, 101, 114, 95, 117, 115, 101, 114, 95, 112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 115, 34, 32, 79, 78, 32, 40, 34, 97, 117, 116, 104, 95, 112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 34, 46, 34, 105, 100, 34, 32, 61, 32, 34, 97, 117, 116, 104, 95, 117, 115, 101, 114, 95, 117, 115, 101, 114, 95, 112, 101, 114},
			op:     "SELECT",
			tables: []string{"auth_permission", "auth_user_user_permissions"},
			sql:    "SELECT DISTINCT \"auth_permission\".\"id\", \"django_content_type\".\"app_label\", \"django_content_type\".\"model\", \"auth_permission\".\"codename\" FROM \"auth_permission\" LEFT OUTER JOIN \"auth_user_user_permissions\" ON (\"auth_permission\".\"id\" = \"auth_user_user_per",
		},
		{
			name:   "Query prepared statement",
			bytes:  []byte{81, 0, 0, 0, 28, 101, 120, 101, 99, 117, 116, 101, 32, 109, 121, 95, 99, 111, 110, 116, 97, 99, 116, 115, 32, 40, 49, 41, 0, 69, 76, 69, 67, 84, 32, 42, 32, 102, 114, 111, 109, 32, 97, 99, 99, 111, 117, 110, 116, 105, 110, 103, 46, 99, 111, 110, 116, 97, 99, 116, 115, 32, 87, 72, 69, 82, 69, 32, 105, 100, 32, 61, 32, 36, 49, 0, 53, 90, 51, 106, 119, 55, 54, 111, 100, 85, 115, 57, 78, 75, 72, 73, 76, 119, 120, 104, 108, 81, 118, 50, 98, 122, 70, 72, 111, 73, 70, 48, 61},
			op:     "EXECUTE",
			tables: []string{"my_contacts"},
			sql:    "execute my_contacts (1)",
		},
		{
			name:  "Query prepared statement bad len",
			bytes: []byte{81, 0, 0, 0, 7, 101, 120, 101, 99, 117, 116, 101, 32, 109, 121, 95, 99, 111, 110, 116, 97, 99, 116, 115, 32, 40, 49, 41, 0, 69, 76, 69, 67, 84, 32, 42, 32, 102, 114, 111, 109, 32, 97, 99, 99, 111, 117, 110, 116, 105, 110, 103, 46, 99, 111, 110, 116, 97, 99, 116, 115, 32, 87, 72, 69, 82, 69, 32, 105, 100, 32, 61, 32, 36, 49, 0, 53, 90, 51, 106, 119, 55, 54, 111, 100, 85, 115, 57, 78, 75, 72, 73, 76, 119, 120, 104, 108, 81, 118, 50, 98, 122, 70, 72, 111, 73, 70, 48, 61},
			op:    "",

			sql: "",
		},
		{
			name:  "small len",
			bytes: []byte{81, 0, 0},
			op:    "",

			sql: "",
		},
		{
			name:  "empty",
			bytes: []byte{},
			op:    "",

			sql: "",
		},
		{
			name:   "MySQL prepared statement",
			bytes:  []byte{36, 0, 0, 0, 3, 0, 1, 69, 88, 69, 67, 85, 84, 69, 32, 109, 121, 95, 97, 99, 116, 111, 114, 115, 32, 85, 83, 73, 78, 71, 32, 64, 97, 99, 116, 111, 114, 95, 105, 100},
			op:     "EXECUTE",
			tables: []string{"my_actors"},
			sql:    "EXECUTE my_actors USING @actor_id",
		},
	} {
		t.Run(ts.name, func(t *testing.T) {
			op, tables, sql, _ := detectSQLPayload(false, largebuf.NewLargeBufferFrom(ts.bytes))
			assert.Equal(t, ts.op, op)
			assert.Equal(t, ts.tables, tables)
			assert.Equal(t, ts.sql, sql)

			op, tables, sql, _ = detectSQLPayload(true, largebuf.NewLargeBufferFrom(ts.bytes))
			assert.Equal(t, ts.op, op)
			assert.Equal(t, ts.tables, tables)
			assert.Equal(t, ts.sql, sql)
		})
	}
}

type asciiSQLTest struct {
	name string
	s    string
	ok   bool
}

func TestIsASCII(t *testing.T) {
	for _, ts := range []asciiSQLTest{
		{
			name: "Positive test",
			s:    "This is a test_.-1234",
			ok:   true,
		},
		{
			name: "Bad char",
			s:    "This is\x00 a test_.-1234",
			ok:   false,
		},
		{
			name: "Empty",
			s:    "",
			ok:   true,
		},
	} {
		t.Run(ts.name, func(t *testing.T) {
			res := isASCII(ts.s)
			assert.Equal(t, ts.ok, res)
		})
	}
}

func TestMinSQLPrintableRun(t *testing.T) {
	// Pinned to the length of "SELECT 1" so that the shortest detectable SQL
	// statement just clears the prefilter threshold. If this changes, audit
	// the SQL detection tests in tcp_detect_transform_test.go.
	assert.Len(t, "SELECT 1", minSQLPrintableRun)
}

func TestIsSQLByte(t *testing.T) {
	t.Run("accepts every printable ASCII byte in [0x20, 0x7F)", func(t *testing.T) {
		for b := 0x20; b < 0x7f; b++ {
			assert.Truef(t, isSQLByte(byte(b)), "byte 0x%02X should be accepted", b)
		}
	})

	t.Run("accepts tab, LF, and CR", func(t *testing.T) {
		for _, b := range []byte{'\t', '\n', '\r'} {
			assert.Truef(t, isSQLByte(b), "whitespace 0x%02X should be accepted", b)
		}
	})

	t.Run("rejects control bytes other than tab/LF/CR", func(t *testing.T) {
		for _, b := range []byte{0x00, 0x01, '\b', '\v', '\f', 0x1B, 0x1F} {
			assert.Falsef(t, isSQLByte(b), "control byte 0x%02X should be rejected", b)
		}
	})

	t.Run("rejects DEL (0x7F)", func(t *testing.T) {
		// 0x7F sits just outside the [0x20, 0x7F) printable range.
		assert.False(t, isSQLByte(0x7f))
	})

	t.Run("rejects bytes with the high bit set", func(t *testing.T) {
		for _, b := range []byte{0x80, 0xA5, 0xC2, 0xFE, 0xFF} {
			assert.Falsef(t, isSQLByte(b), "high-bit byte 0x%02X should be rejected", b)
		}
	})
}

func TestFirstSQLRun(t *testing.T) {
	t.Run("returns -1 when the buffer is shorter than minLen", func(t *testing.T) {
		assert.Equal(t, -1, firstSQLRun([]byte("hi"), 5))
		assert.Equal(t, -1, firstSQLRun(nil, 1))
		assert.Equal(t, -1, firstSQLRun([]byte{}, 1))
	})

	t.Run("returns 0 when the whole buffer is printable", func(t *testing.T) {
		assert.Equal(t, 0, firstSQLRun([]byte("SELECT 1"), 8))
		assert.Equal(t, 0, firstSQLRun([]byte("SELECT * FROM users"), 8))
	})

	t.Run("returns 0 when the buffer is exactly minLen and all printable", func(t *testing.T) {
		assert.Equal(t, 0, firstSQLRun([]byte("ABCDEFGH"), 8))
	})

	t.Run("returns the start of a qualifying run that follows a binary prefix", func(t *testing.T) {
		// 5 bytes of binary, then "SELECT 1" (8 printable bytes).
		buf := append([]byte{0x00, 0x01, 0xff, 0xfe, 0x80}, []byte("SELECT 1")...)
		assert.Equal(t, 5, firstSQLRun(buf, 8))
	})

	t.Run("returns -1 when no printable run reaches minLen", func(t *testing.T) {
		// Three 4-byte printable islands separated by binary; none qualifies.
		buf := []byte("ABCD\x00XYZW\xffPQRS")
		assert.Equal(t, -1, firstSQLRun(buf, 8))
	})

	t.Run("skips a short run and finds a later qualifying one", func(t *testing.T) {
		// 4 printable bytes, a binary byte, then 8 printable bytes.
		buf := append([]byte("ABCD\x00"), []byte("SELECT 1")...)
		assert.Equal(t, 5, firstSQLRun(buf, 8))
	})

	t.Run("counts tab, LF, and CR as part of a run", func(t *testing.T) {
		// "S\tE\nL\rE\tCT" = 9 bytes, all SQL-plausible.
		buf := []byte("S\tE\nL\rE\tCT")
		assert.Equal(t, 0, firstSQLRun(buf, 8))
	})

	t.Run("returns the earliest qualifying run when several exist", func(t *testing.T) {
		// Two 8+ byte printable runs separated by binary; the first one wins.
		buf := append([]byte("FIRSTONE\x00"), []byte("SECONDONE")...)
		assert.Equal(t, 0, firstSQLRun(buf, 8))
	})

	t.Run("returns the correct offset when a single binary byte precedes a qualifying run", func(t *testing.T) {
		// Exercises the i - minLen + 1 arithmetic at the boundary.
		buf := []byte("\x00SELECT 1")
		assert.Equal(t, 1, firstSQLRun(buf, 8))
	})

	t.Run("DEL byte interrupts a run", func(t *testing.T) {
		// 0x7F is not SQL-plausible, so "SELECT" (6 chars) is too short and
		// the run only qualifies starting at the space after 0x7F.
		buf := []byte("SELECT\x7f 1 FROM x")
		assert.Equal(t, 7, firstSQLRun(buf, 8))
	})

	t.Run("high-bit bytes interrupt a run", func(t *testing.T) {
		// Half of a UTF-8 emoji in the middle of otherwise-printable text.
		buf := []byte("SELECT\xc2\xa9 1 FROM x")
		// The qualifying run starts at the space (index 8) and runs to end.
		assert.Equal(t, 8, firstSQLRun(buf, 8))
	})
}
