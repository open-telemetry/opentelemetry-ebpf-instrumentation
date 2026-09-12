// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

// Symfony config parsing starts at config/routes.yaml, and YAML files under config/routes.
// Local YAML imports are followed recursively with their prefixes, while attribute imports reuse routes harvested
// from PHP files. symfonyConfigTraversal prevents import cycles and permits only one file under multiple prefixes.
//
// extractSymfonyConfigRoutes
//
//	 -> symfonyYAMLEntries
//	    -> extractSymfonyYAMLFile
//
//		   -> symfonyConfigTraversal.enter / leave
//		   -> extractSymfonyYAMLMapping
//		      -> direct path routes
//		      -> YAML resource: extractSymfonyYAMLFile
//		      -> attribute resource: addImportedSymfonyAttributes
func extractSymfonyConfigRoutes(projectRoot string, attributes map[string][]string, routes routeSet) map[string]struct{} {
	traversal := newSymfonyConfigTraversal()
	imported := map[string]struct{}{}

	for _, entry := range symfonyYAMLEntries(projectRoot) {
		extractSymfonyYAMLFile(projectRoot, entry, "", traversal, attributes, imported, routes)
	}

	return imported
}
