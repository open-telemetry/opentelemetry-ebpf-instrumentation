// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "strings"

// This file handles Laravel's RESTful resource-controller routes, for example:
//
//	Route::resource('photos', PhotoController::class)->only(['index', 'show']);
//	Route::apiResource('photos.comments', PhotoCommentController::class)->shallow();
//	Route::resources(['photos' => PhotoController::class, 'posts' => PostController::class]);
//
// Called from laravel.go's extractCall once it recognises one of these
// method names. Call flow:
//
//	extractLaravelResource / extractLaravelResourceBatch
//	  -> laravelResourceOptions
//	    -> defaultLaravelResourceActions   baseline actions for the method
//	    -> applyLaravelResourceArray       options array, like only/except/shallow
//	    -> resourceActionNames             ->only()/->except() modifier calls
//	  -> addLaravelResource
//	    -> laravelResourcePaths            builds the collection/member URL templates
//	      -> resourceParameter             handles resource name into {param}
var laravelResourceActions = []string{"index", "create", "store", "show", "edit", "update", "destroy"}

func isLaravelResourceMethod(method string) bool {
	switch method {
	case "resource", "apiresource", "singleton", "apisingleton":
		return true
	default:
		return false
	}
}

func isLaravelResourceBatchMethod(method string) bool {
	switch method {
	case "resources", "apiresources", "singletons", "apisingletons", "softdeletableresources":
		return true
	default:
		return false
	}
}

func extractLaravelResource(prefix, method string, calls []laravelCall, routes routeSet) {
	name, ok := staticStringArgument(calls[0].arguments, 0)
	if !ok {
		name, ok = namedLiteralArgument(calls[0].arguments, "name")
	}

	if !ok {
		return
	}

	optionArray := laravelResourceOptionArgument(calls[0].arguments, 2)
	if namedOptions, found := namedArgument(calls[0].arguments, "options"); found {
		optionArray = namedOptions
	}

	options := laravelResourceOptions(
		method,
		optionArray,
		calls[1:],
	)

	addLaravelResource(prefix, name, options, routes)
}

func extractLaravelResourceBatch(prefix, method string, calls []laravelCall, routes routeSet) {
	if len(calls[0].arguments) == 0 {
		return
	}

	resources := calls[0].arguments[0]
	if namedResources, found := namedArgument(calls[0].arguments, "resources"); found {
		resources = namedResources
	}

	optionArray := laravelResourceOptionArgument(calls[0].arguments, 1)
	if namedOptions, found := namedArgument(calls[0].arguments, "options"); found {
		optionArray = namedOptions
	}

	for _, name := range laravelResourceNames(resources) {
		options := laravelResourceOptions(
			laravelBatchResourceMethod(method),
			optionArray,
			calls[1:],
		)
		addLaravelResource(prefix, name, options, routes)
	}
}

func laravelBatchResourceMethod(method string) string {
	switch method {
	case "apiresources":
		return "apiresource"
	case "singletons":
		return "singleton"
	case "apisingletons":
		return "apisingleton"
	default:
		return "resource"
	}
}

func laravelResourceNames(argument []token) []string {
	if len(argument) < 2 || argument[0].value != "[" || argument[len(argument)-1].value != "]" {
		return nil
	}

	var names []string
	for _, item := range splitOnTopLevelCommas(argument[1 : len(argument)-1]) {
		if len(item) >= 3 && item[0].kind == tokenString && item[1].value == "=>" {
			names = append(names, item[0].value)
		}
	}

	return names
}

type laravelResourceConfig struct {
	actions       map[string]struct{}
	onlyActions   []string
	exceptActions []string
	hasOnly       bool
	shallow       bool
	singleton     bool
}

func laravelResourceOptions(method string, optionArray []token, modifiers []laravelCall) laravelResourceConfig {
	actions := defaultLaravelResourceActions(method)

	config := laravelResourceConfig{
		actions:   actions,
		singleton: strings.Contains(method, "singleton"),
	}

	config = applyLaravelResourceArray(config, optionArray)

	for _, modifier := range modifiers {
		switch strings.ToLower(modifier.name) {
		case "only":
			config.onlyActions = resourceActionNames(modifier.arguments)
			config.hasOnly = true
		case "except":
			config.exceptActions = resourceActionNames(modifier.arguments)
		case "shallow":
			config.shallow = true
		case "creatable":
			addResourceActions(config.actions, "store", "destroy")
			if method == "singleton" {
				addResourceActions(config.actions, "create")
			}
		case "destroyable":
			addResourceActions(config.actions, "destroy")
		}
	}

	return applyLaravelResourceActionSelection(config)
}

func defaultLaravelResourceActions(method string) map[string]struct{} {
	var actions []string
	switch method {
	case "singleton":
		actions = []string{"show", "edit", "update"}
	case "apisingleton":
		actions = []string{"store", "show", "update", "destroy"}
	case "apiresource":
		actions = []string{"index", "store", "show", "update", "destroy"}
	default:
		actions = laravelResourceActions
	}

	return selectedResourceActions(actions)
}

func addResourceActions(actions map[string]struct{}, names ...string) {
	for _, name := range names {
		actions[name] = struct{}{}
	}
}

func laravelResourceOptionArgument(arguments [][]token, index int) []token {
	if index < 0 || index >= len(arguments) {
		return nil
	}

	return arguments[index]
}

func applyLaravelResourceArray(config laravelResourceConfig, argument []token) laravelResourceConfig {
	if len(argument) < 2 || argument[0].value != "[" || argument[len(argument)-1].value != "]" {
		return config
	}

	for _, item := range splitOnTopLevelCommas(argument[1 : len(argument)-1]) {
		if len(item) < 3 || item[0].kind != tokenString || item[1].value != "=>" {
			continue
		}
		name := item[0].value
		value := item[2:]
		switch name {
		case "only":
			config.onlyActions = resourceActionNames([][]token{value})
			config.hasOnly = true
		case "except":
			config.exceptActions = resourceActionNames([][]token{value})
		case "shallow":
			config.shallow = len(value) == 1 && equalName(value[0], "true")
		}
	}

	return applyLaravelResourceActionSelection(config)
}

func applyLaravelResourceActionSelection(config laravelResourceConfig) laravelResourceConfig {
	if config.hasOnly {
		config.actions = selectedResourceActions(config.onlyActions)
	}

	for _, action := range config.exceptActions {
		delete(config.actions, action)
	}

	return config
}

func resourceActionNames(arguments [][]token) []string {
	var actions []string
	for _, argument := range arguments {
		if len(argument) == 1 && argument[0].kind == tokenString {
			actions = append(actions, argument[0].value)
			continue
		}

		if len(argument) >= 2 && argument[0].value == "[" && argument[len(argument)-1].value == "]" {
			for _, item := range splitOnTopLevelCommas(argument[1 : len(argument)-1]) {
				if len(item) == 1 && item[0].kind == tokenString {
					actions = append(actions, item[0].value)
				}
			}
		}
	}

	return actions
}

func selectedResourceActions(actions []string) map[string]struct{} {
	selected := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		selected[action] = struct{}{}
	}

	return selected
}

func addLaravelResource(prefix, name string, config laravelResourceConfig, routes routeSet) {
	collection, member := laravelResourcePaths(name, config)
	paths := map[string]string{
		"index": collection, "create": joinRoutes(collection, "create"), "store": collection,
		"show": member, "edit": joinRoutes(member, "edit"), "update": member, "destroy": member,
	}

	for action := range config.actions {
		if path, ok := paths[action]; ok {
			routes.add(joinRoutes(prefix, path))
		}
	}
}

func laravelResourcePaths(name string, config laravelResourceConfig) (string, string) {
	slashParts := strings.FieldsFunc(name, func(char rune) bool { return char == '/' })
	if len(slashParts) == 0 {
		return "", ""
	}

	prefix := ""
	for _, part := range slashParts[:len(slashParts)-1] {
		prefix = joinRoutes(prefix, part)
	}

	resourceParts := strings.FieldsFunc(slashParts[len(slashParts)-1], func(char rune) bool { return char == '.' })
	if len(resourceParts) == 0 {
		return "", ""
	}

	collection := prefix
	for index, part := range resourceParts {
		collection = joinRoutes(collection, part)
		if index < len(resourceParts)-1 {
			collection = joinRoutes(collection, resourceParameter(part))
		}
	}

	if config.singleton {
		return collection, collection
	}

	lastResource := resourceParts[len(resourceParts)-1]
	member := joinRoutes(collection, resourceParameter(lastResource))
	if config.shallow && len(resourceParts) > 1 {
		member = joinRoutes(prefix, lastResource, resourceParameter(lastResource))
	}

	return collection, member
}

func resourceParameter(resource string) string {
	name := resource
	if strings.HasSuffix(name, "ies") && len(name) > 3 {
		name = strings.TrimSuffix(name, "ies") + "y"
	} else {
		name = strings.TrimSuffix(name, "s")
	}

	name = strings.ReplaceAll(name, "-", "_")
	return "{" + name + "}"
}
