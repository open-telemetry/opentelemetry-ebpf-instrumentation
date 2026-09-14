// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

// This file reads bootstrap/app.php to find the URL prefix Laravel applies
// to routes/api.php, for example:
//
//	return Application::configure(basePath: dirname(__DIR__))
//	    ->withRouting(
//	        web: __DIR__.'/../routes/web.php',
//	        api: __DIR__.'/../routes/api.php',
//	        apiPrefix: 'api',
//	    )->create();
//
// Call flow:
//
//	laravelAPIPrefix
//	  -> hasLaravelAPIRouteFile   confirms the "api:" argument is routes/api.php
//	  -> namedArgument            reads the "apiPrefix:" argument
func laravelAPIPrefix(root string) string {
	data, _, err := langtools.ReadMetadataFile(filepath.Join(root, "bootstrap", "app.php"), maxPHPFileBytes)
	if err != nil || data == nil {
		return ""
	}

	tokens := lexPHP(data)
	for pos := 0; pos+1 < len(tokens); pos++ {
		if !equalName(tokens[pos], "withRouting") || tokens[pos+1].value != "(" {
			continue
		}

		arguments := callArguments(tokens, pos+1)
		if !hasLaravelAPIRouteFile(arguments) {
			return ""
		}

		if _, configured := namedArgument(arguments, "apiPrefix"); !configured {
			return "api"
		}

		prefix, _ := namedLiteralArgument(arguments, "apiPrefix")
		return prefix
	}
	return ""
}

func hasLaravelAPIRouteFile(arguments [][]token) bool {
	argument, ok := namedArgument(arguments, "api")
	if !ok {
		return false
	}

	for _, tok := range argument {
		path := strings.TrimPrefix(filepath.ToSlash(tok.value), "./")
		if tok.kind == tokenString && (path == "routes/api.php" || strings.HasSuffix(path, "/routes/api.php")) {
			return true
		}
	}

	return false
}

func namedLiteralArgument(arguments [][]token, name string) (string, bool) {
	argument, ok := namedArgument(arguments, name)
	if !ok || len(argument) != 1 || argument[0].kind != tokenString {
		return "", false
	}

	return argument[0].value, true
}

func namedArgument(arguments [][]token, name string) ([]token, bool) {
	for _, argument := range arguments {
		if len(argument) >= 3 && argument[0].kind == tokenName && argument[0].value == name && argument[1].value == ":" {
			return argument[2:], true
		}
	}

	return nil, false
}
