// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
)

func TestParseHostnameFromDSN(t *testing.T) {
	tests := []struct {
		name     string
		driver   string
		dsn      string
		expected string
	}{
		// MySQL tests
		{
			name:     "MySQL TCP with host and port",
			driver:   "mysql",
			dsn:      "user:password@tcp(localhost:3306)/dbname",
			expected: "localhost",
		},
		{
			name:     "MySQL TCP with IP",
			driver:   "mysql",
			dsn:      "root:pass@tcp(127.0.0.1:3306)/mydb",
			expected: "127.0.0.1",
		},
		{
			name:     "MySQL with hostname only",
			driver:   "mysql",
			dsn:      "user:password@tcp(mysql)/dbname",
			expected: "mysql",
		},
		{
			name:     "MySQL with parameters",
			driver:   "mysql",
			dsn:      "user:pass@tcp(db.example.com:3306)/dbname?charset=utf8mb4&parseTime=true",
			expected: "db.example.com",
		},
		{
			name:     "MySQL minimal DSN",
			driver:   "mysql",
			dsn:      "user@tcp(mysql:3306)/db",
			expected: "mysql",
		},

		// PostgreSQL tests - key=value format
		{
			name:     "PostgreSQL key=value with host and port",
			driver:   "postgres",
			dsn:      "user=postgres dbname=sqltest sslmode=disable password=postgres host=sqlserver port=5432",
			expected: "sqlserver",
		},
		{
			name:     "PostgreSQL key=value host only",
			driver:   "postgres",
			dsn:      "host=localhost user=postgres dbname=test",
			expected: "localhost",
		},
		{
			name:     "PostgreSQL key=value different order",
			driver:   "postgres",
			dsn:      "dbname=mydb host=db.example.com port=5433 user=admin password=secret",
			expected: "db.example.com",
		},

		// PostgreSQL tests - URL format
		{
			name:     "PostgreSQL URL format",
			driver:   "postgres",
			dsn:      "postgres://user:pass@localhost:5432/dbname?sslmode=disable",
			expected: "localhost",
		},
		{
			name:     "PostgreSQL URL without port",
			driver:   "postgres",
			dsn:      "postgresql://user@localhost/dbname",
			expected: "localhost",
		},

		// Edge cases
		{
			name:     "Empty DSN",
			driver:   "mysql",
			dsn:      "",
			expected: "",
		},
		{
			name:     "Unknown driver",
			driver:   "unknown",
			dsn:      "some:dsn@string",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHostnameFromDSN(tt.driver, tt.dsn)
			if result != tt.expected {
				t.Errorf("parseHostnameFromDSN(%q, %q) = %q, expected %q", tt.driver, tt.dsn, result, tt.expected)
			}
		})
	}
}
