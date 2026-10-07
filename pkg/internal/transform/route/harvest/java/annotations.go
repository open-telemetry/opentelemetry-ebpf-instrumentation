// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"

import (
	"slices"

	"go.opentelemetry.io/obi/pkg/internal/jvmtools/classfile"
)

var springMappingAnnotations = map[string]struct{}{
	"Lorg/springframework/web/bind/annotation/RequestMapping;": {},
	"Lorg/springframework/web/bind/annotation/GetMapping;":     {},
	"Lorg/springframework/web/bind/annotation/PostMapping;":    {},
	"Lorg/springframework/web/bind/annotation/PutMapping;":     {},
	"Lorg/springframework/web/bind/annotation/DeleteMapping;":  {},
	"Lorg/springframework/web/bind/annotation/PatchMapping;":   {},
}

var jaxrsPathAnnotations = map[string]struct{}{
	"Ljakarta/ws/rs/Path;": {},
	"Ljavax/ws/rs/Path;":   {},
}

var jaxrsMethodAnnotations = map[string]struct{}{
	"Ljakarta/ws/rs/GET;":     {},
	"Ljakarta/ws/rs/POST;":    {},
	"Ljakarta/ws/rs/PUT;":     {},
	"Ljakarta/ws/rs/DELETE;":  {},
	"Ljakarta/ws/rs/PATCH;":   {},
	"Ljakarta/ws/rs/HEAD;":    {},
	"Ljakarta/ws/rs/OPTIONS;": {},
	"Ljavax/ws/rs/GET;":       {},
	"Ljavax/ws/rs/POST;":      {},
	"Ljavax/ws/rs/PUT;":       {},
	"Ljavax/ws/rs/DELETE;":    {},
	"Ljavax/ws/rs/PATCH;":     {},
	"Ljavax/ws/rs/HEAD;":      {},
	"Ljavax/ws/rs/OPTIONS;":   {},
}

var micronautControllerAnnotations = map[string]struct{}{
	"Lio/micronaut/http/annotation/Controller;": {},
}

var micronautMethodAnnotations = map[string]struct{}{
	"Lio/micronaut/http/annotation/Get;":     {},
	"Lio/micronaut/http/annotation/Post;":    {},
	"Lio/micronaut/http/annotation/Put;":     {},
	"Lio/micronaut/http/annotation/Delete;":  {},
	"Lio/micronaut/http/annotation/Patch;":   {},
	"Lio/micronaut/http/annotation/Head;":    {},
	"Lio/micronaut/http/annotation/Options;": {},
	"Lio/micronaut/http/annotation/Trace;":   {},
}

var quarkusRouteBaseAnnotations = map[string]struct{}{
	"Lio/quarkus/vertx/web/RouteBase;": {},
}

var quarkusRouteAnnotations = map[string]struct{}{
	"Lio/quarkus/vertx/web/Route;": {},
}

var quarkusRouteContainerAnnotations = map[string]struct{}{
	"Lio/quarkus/vertx/web/Route$Routes;": {},
}

func routesFromClass(class *classfile.Class) []string {
	classPaths := classRouteFragments(class.ClassAnnotations)
	if len(classPaths) == 0 {
		classPaths = []string{""}
	}

	var routes []string
	for _, annotations := range class.MethodAnnotations {
		paths, ok := methodRouteFragments(annotations)
		if !ok {
			continue
		}
		if len(paths) == 0 {
			paths = []string{""}
		}

		for _, cp := range classPaths {
			for _, path := range paths {
				routes = append(routes, joinRoutePaths(cp, path))
			}
		}
	}

	return routes
}

func classRouteFragments(annotations []classfile.Annotation) []string {
	var paths []string
	for _, a := range annotations {
		switch {
		case hasAnnotation(springMappingAnnotations, a.Descriptor):
			paths = append(paths, annotationPaths(a, "value", "path")...)
		case hasAnnotation(jaxrsPathAnnotations, a.Descriptor):
			paths = append(paths, annotationPaths(a, "value")...)
		case hasAnnotation(micronautControllerAnnotations, a.Descriptor):
			paths = append(paths, annotationPaths(a, "value")...)
		case hasAnnotation(quarkusRouteBaseAnnotations, a.Descriptor):
			paths = append(paths, annotationPaths(a, "value", "path")...)
		}
	}
	return uniqueStrings(paths)
}

func methodRouteFragments(annotations []classfile.Annotation) ([]string, bool) {
	var paths []string
	isRoute := false
	for _, a := range annotations {
		switch {
		case hasAnnotation(springMappingAnnotations, a.Descriptor):
			isRoute = true
			paths = append(paths, annotationPaths(a, "value", "path")...)
		case hasAnnotation(jaxrsPathAnnotations, a.Descriptor):
			isRoute = true
			paths = append(paths, annotationPaths(a, "value")...)
		case hasAnnotation(jaxrsMethodAnnotations, a.Descriptor):
			isRoute = true
		case hasAnnotation(micronautMethodAnnotations, a.Descriptor):
			isRoute = true
			paths = append(paths, annotationPaths(a, "value", "uri")...)
		case hasAnnotation(quarkusRouteAnnotations, a.Descriptor):
			quarkusPaths, ok := quarkusRoutePaths(a)
			if !ok {
				continue
			}
			isRoute = true
			paths = append(paths, quarkusPaths...)
		case hasAnnotation(quarkusRouteContainerAnnotations, a.Descriptor):
			for _, nested := range a.Nested {
				if !hasAnnotation(quarkusRouteAnnotations, nested.Descriptor) {
					continue
				}
				quarkusPaths, ok := quarkusRoutePaths(nested)
				if !ok {
					continue
				}
				isRoute = true
				paths = append(paths, quarkusPaths...)
			}
		}
	}
	return uniqueStrings(paths), isRoute
}

func quarkusRoutePaths(a classfile.Annotation) ([]string, bool) {
	if len(a.Elements["regex"]) > 0 {
		return nil, false
	}
	return annotationPaths(a, "value", "path"), true
}

func annotationPaths(a classfile.Annotation, names ...string) []string {
	var paths []string
	for _, name := range names {
		for _, path := range a.Elements[name] {
			if slices.Contains(paths, path) {
				continue
			}
			paths = append(paths, path)
		}
	}
	return paths
}

func hasAnnotation(annotations map[string]struct{}, descriptor string) bool {
	_, ok := annotations[descriptor]
	return ok
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
