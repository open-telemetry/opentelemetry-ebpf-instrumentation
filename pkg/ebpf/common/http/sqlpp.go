// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

// sqlppRequest represents the JSON structure of a SQL++ query request
type sqlppRequest struct {
	Statement string `json:"statement"`
	QueryCtx  string `json:"query_context"`
}

// SQLPPSpan detects and enriches SQL++ spans (Couchbase and other SQL++ databases)
func SQLPPSpan(baseSpan *request.Span, req *http.Request, resp *http.Response, endpointPatterns []string) (request.Span, bool) {
	// Must match endpoint pattern first
	if !matchesEndpointPattern(req, endpointPatterns) {
		return *baseSpan, false
	}

	sqlppInfo, err := parseSQLPPRequest(req)
	if err != nil {
		slog.Debug("parse SQL++ request", "error", err)
		return *baseSpan, false
	}

	// Determine db system: N1QL header means Couchbase, otherwise other_sql
	dbSystem := "other_sql"
	if hasN1QLVersion(resp) {
		dbSystem = "couchbase"
	}

	// Use the standard SQL parser to extract operation and table
	operation, table := sqlprune.SQLParseOperationAndTable(sqlppInfo.Statement)
	if operation == "" {
		operation = "query" // default operation
	}

	// Parse the table path into bucket and collection
	// Format: bucket.scope.collection or just identifier
	bucket, collection := parseSQLPPTablePath(table, sqlppInfo.QueryCtx != "")

	// If bucket not in table path, try to get from query_context or request fields
	if bucket == "" {
		bucket = extractSQLPPNamespace(sqlppInfo)
	}

	// Use existing span fields for SQL-like attributes
	// Note: Don't overwrite Path - it's needed for url.full (the HTTP route)
	baseSpan.SubType = request.HTTPSubtypeSQLPP
	baseSpan.Route = collection              // db.collection.name (scope.collection)
	baseSpan.Statement = sqlppInfo.Statement // db.query.text
	baseSpan.DBNamespace = bucket            // db.namespace (bucket)
	baseSpan.DBSystem = dbSystem             // db.system.name
	baseSpan.Method = operation              // db.operation.name

	return *baseSpan, true
}

// matchesEndpointPattern checks if request URL matches any endpoint pattern
func matchesEndpointPattern(req *http.Request, patterns []string) bool {
	if req == nil || len(patterns) == 0 {
		return false
	}
	path := req.URL.Path
	for _, pattern := range patterns {
		if strings.HasSuffix(path, pattern) || path == pattern {
			return true
		}
	}
	return false
}

// hasN1QLVersion checks if the response Content-Type header contains a version parameter
// that ends with "-N1QL" (e.g., "version=2.0.0-N1QL"), indicating Couchbase
func hasN1QLVersion(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	contentType := resp.Header.Get("Content-Type")
	// Split by semicolons to get individual parameters
	parts := strings.Split(contentType, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Look for version= parameter
		if strings.HasPrefix(strings.ToLower(part), "version=") {
			// Extract the version value
			value := strings.TrimPrefix(part, part[:8]) // Remove "version=" (case-insensitive handled by HasPrefix)
			return strings.HasSuffix(value, "-N1QL")
		}
	}
	return false
}

// parseSQLPPTablePath parses a SQL++ table path into bucket and collection
// Format: `bucket`.`scope`.`collection` -> bucket="bucket", collection="scope.collection"
// Format: `identifier` with hasQueryContext=true -> bucket="", collection="identifier"
// Format: `identifier` with hasQueryContext=false -> bucket="identifier", collection=""
func parseSQLPPTablePath(table string, hasQueryContext bool) (bucket, collection string) {
	if table == "" {
		return "", ""
	}

	parts := strings.Split(table, ".")
	switch len(parts) {
	case 1:
		// Just a single identifier - interpretation depends on context
		if hasQueryContext {
			// When query_context is set, this is the collection name
			return "", parts[0]
		}
		// When no query_context, this is the bucket name (legacy mode)
		return parts[0], ""
	case 3:
		// bucket.scope.collection
		return parts[0], parts[1] + "." + parts[2]
	default:
		// Unexpected format, return as-is
		return "", table
	}
}

// parseSQLPPRequest parses the SQL++ query request body
func parseSQLPPRequest(req *http.Request) (*sqlppRequest, error) {
	if req == nil || req.Body == nil {
		return nil, errors.New("nil request or body")
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read SQL++ request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	var sqlppReq sqlppRequest

	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// Handle form-encoded requests
		sqlppReq.Statement = extractFormValue(string(reqB), "statement")
		sqlppReq.QueryCtx = extractFormValue(string(reqB), "query_context")
	} else {
		// Handle JSON requests
		if err := json.Unmarshal(reqB, &sqlppReq); err != nil {
			// Try to extract statement from raw body if JSON parsing fails
			sqlppReq.Statement = string(reqB)
		}
	}

	if sqlppReq.Statement == "" {
		return nil, errors.New("no statement found in SQL++ request")
	}

	return &sqlppReq, nil
}

// extractFormValue extracts a value from form-encoded data
func extractFormValue(data, key string) string {
	pairs := strings.Split(data, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 && kv[0] == key {
			// URL decode the value
			return strings.ReplaceAll(kv[1], "+", " ")
		}
	}
	return ""
}

// queryContextPattern parses query_context format: default:bucket.scope
var queryContextPattern = regexp.MustCompile(`^(?:default:)?([a-zA-Z0-9_-]+)(?:\.([a-zA-Z0-9_-]+))?$`)

// extractSQLPPNamespace extracts namespace (bucket) from SQL++ request
func extractSQLPPNamespace(sqlppReq *sqlppRequest) string {
	// First, try to get from query_context (format: "default:bucket.scope" or "bucket.scope")
	if sqlppReq.QueryCtx != "" {
		matches := queryContextPattern.FindStringSubmatch(sqlppReq.QueryCtx)
		if len(matches) > 1 {
			return matches[1] // bucket
		}
	}

	return ""
}
