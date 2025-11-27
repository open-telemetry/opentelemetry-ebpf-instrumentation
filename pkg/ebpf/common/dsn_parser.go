// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

// parseHostnameFromDSN extracts hostname:port from DSN string
// based on the driver name to handle driver-specific formats.
// Uses the actual driver parsers for reliability.
func parseHostnameFromDSN(driver, dsn string) string {
	if dsn == "" {
		return ""
	}

	switch driver {
	case "mysql":
		return parseMySQLDSN(dsn)
	case "postgres", "postgresql":
		return parsePostgresDSN(dsn)
	default:
		// Unknown driver - no parsing
		return ""
	}
}

// parseMySQLDSN uses the official MySQL driver parser
// Returns only the hostname (without port)
func parseMySQLDSN(dsn string) string {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return ""
	}

	addr := cfg.Addr
	// Strip port if present
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}

	return addr
}

// parsePostgresDSN uses the pgx parser for PostgreSQL DSNs
// Returns only the hostname (without port)
func parsePostgresDSN(dsn string) string {
	config, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return ""
	}

	return config.Host
}
