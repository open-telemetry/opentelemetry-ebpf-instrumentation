// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsLaravelResourceMethod(t *testing.T) {
	for _, method := range []string{"resource", "apiresource", "singleton", "apisingleton"} {
		assert.True(t, isLaravelResourceMethod(method), method)
	}

	for _, method := range []string{"resources", "get", "", "Resource"} {
		assert.False(t, isLaravelResourceMethod(method), method)
	}
}

func TestIsLaravelResourceBatchMethod(t *testing.T) {
	for _, method := range []string{"resources", "apiresources", "singletons", "apisingletons", "softdeletableresources"} {
		assert.True(t, isLaravelResourceBatchMethod(method), method)
	}

	for _, method := range []string{"resource", "get", "", "Resources"} {
		assert.False(t, isLaravelResourceBatchMethod(method), method)
	}
}

func TestExtractLaravelResource(t *testing.T) {
	_, calls := parseLaravelCallChain(t, `Route::resource('photos.comments', CommentController::class)->only('show')->shallow()`)
	routes := newRouteSet()

	extractLaravelResource("/api", "resource", calls, routes)

	assert.Equal(t, routeSet{"/api/comments/{comment}": {}}, routes)

	_, dynamicCalls := parseLaravelCallChain(t, `Route::resource($resource, ResourceController::class)`)
	extractLaravelResource("/api", "resource", dynamicCalls, routes)
	assert.Equal(t, routeSet{"/api/comments/{comment}": {}}, routes)
}

func TestExtractLaravelResourceAppliesChainedOptionsAfterArrayOptions(t *testing.T) {
	_, calls := parseLaravelCallChain(t, `Route::resource(
        'posts',
        PostController::class,
        ['only' => ['index']],
    )->only('show')`)
	routes := newRouteSet()

	extractLaravelResource("", "resource", calls, routes)

	assert.Equal(t, routeSet{"/posts/{post}": {}}, routes)
}

func TestExtractLaravelResourceSupportsNamedArguments(t *testing.T) {
	_, calls := parseLaravelCallChain(t, `Route::resource(
        name: 'posts',
        controller: PostController::class,
        options: ['only' => ['show']],
    )`)
	routes := newRouteSet()

	extractLaravelResource("", "resource", calls, routes)

	assert.Equal(t, routeSet{"/posts/{post}": {}}, routes)
}

func TestExtractLaravelResourceBatch(t *testing.T) {
	_, calls := parseLaravelCallChain(t, `Route::apiResources([
        'users' => UserController::class,
        'photos' => PhotoController::class,
    ], ['only' => ['show']])`)
	routes := newRouteSet()

	extractLaravelResourceBatch("/api", "apiresources", calls, routes)

	assert.Equal(t, routeSet{
		"/api/users/{user}":   {},
		"/api/photos/{photo}": {},
	}, routes)

	extractLaravelResourceBatch("/api", "resources", []laravelCall{{}}, routes)
	assert.Len(t, routes, 2)
}

func TestExtractLaravelResourceBatchSupportsNamedArguments(t *testing.T) {
	_, calls := parseLaravelCallChain(t, `Route::apiResources(
		resources: ['users' => UserController::class],
		options: ['only' => ['show']],
	)`)
	routes := newRouteSet()

	extractLaravelResourceBatch("", "apiresources", calls, routes)

	assert.Equal(t, routeSet{"/users/{user}": {}}, routes)
}

func TestLaravelBatchResourceMethod(t *testing.T) {
	tests := map[string]string{
		"apiresources":           "apiresource",
		"singletons":             "singleton",
		"apisingletons":          "apisingleton",
		"resources":              "resource",
		"softdeletableresources": "resource",
	}

	for method, want := range tests {
		assert.Equal(t, want, laravelBatchResourceMethod(method), method)
	}
}

func TestLaravelResourceNames(t *testing.T) {
	arguments := callArguments(lexPHP([]byte(`resources([
        'users' => UserController::class,
        'photos' => PhotoController::class,
        1 => IgnoredController::class,
        'missing-value' =>,
    ])`)), 1)

	assert.Equal(t, []string{"users", "photos"}, laravelResourceNames(arguments[0]))
	assert.Nil(t, laravelResourceNames(nil))
	assert.Nil(t, laravelResourceNames(lexPHP([]byte(`'users' => UserController::class`))))
	assert.Nil(t, laravelResourceNames(lexPHP([]byte(`['users' => UserController::class`))))
}

func TestLaravelResourceOptions(t *testing.T) {
	_, calls := parseLaravelCallChain(t, `Route::resource('posts', PostController::class)->except('edit')->shallow()`)
	config := laravelResourceOptions("resource", nil, calls[1:])
	assert.Equal(t, selectedResourceActions([]string{"index", "create", "store", "show", "update", "destroy"}), config.actions)
	assert.True(t, config.shallow)
	assert.False(t, config.singleton)

	_, singletonCalls := parseLaravelCallChain(t, `Route::singleton('profile', ProfileController::class)->creatable()`)
	singleton := laravelResourceOptions("singleton", nil, singletonCalls[1:])
	assert.Equal(t, selectedResourceActions([]string{"create", "store", "show", "edit", "update", "destroy"}), singleton.actions)
	assert.True(t, singleton.singleton)

	_, destroyableCalls := parseLaravelCallChain(t, `Route::singleton('profile', ProfileController::class)->destroyable()`)
	destroyable := laravelResourceOptions("singleton", nil, destroyableCalls[1:])
	assert.Contains(t, destroyable.actions, "destroy")

	_, apiCalls := parseLaravelCallChain(t, `Route::apiSingleton('profile', ProfileController::class)->creatable()`)
	apiSingleton := laravelResourceOptions("apisingleton", nil, apiCalls[1:])
	assert.Equal(t, selectedResourceActions([]string{"store", "show", "update", "destroy"}), apiSingleton.actions)

	_, reorderedCalls := parseLaravelCallChain(t, `Route::resource('posts', PostController::class)->except('show')->only(['index', 'show'])`)
	reordered := laravelResourceOptions("resource", nil, reorderedCalls[1:])
	assert.Equal(t, selectedResourceActions([]string{"index"}), reordered.actions)
}

func TestDefaultLaravelResourceActions(t *testing.T) {
	tests := map[string][]string{
		"resource":     {"index", "create", "store", "show", "edit", "update", "destroy"},
		"apiresource":  {"index", "store", "show", "update", "destroy"},
		"singleton":    {"show", "edit", "update"},
		"apisingleton": {"store", "show", "update", "destroy"},
	}

	for method, actions := range tests {
		assert.Equal(t, selectedResourceActions(actions), defaultLaravelResourceActions(method), method)
	}

	first := defaultLaravelResourceActions("resource")
	delete(first, "index")
	assert.Contains(t, defaultLaravelResourceActions("resource"), "index")
}

func TestAddResourceActions(t *testing.T) {
	actions := selectedResourceActions([]string{"show"})

	addResourceActions(actions, "store", "destroy", "show")

	assert.Equal(t, selectedResourceActions([]string{"show", "store", "destroy"}), actions)
}

func TestLaravelResourceOptionArgument(t *testing.T) {
	arguments := [][]token{{{kind: tokenString, value: "users"}}, {{kind: tokenString, value: "controller"}}}

	assert.Equal(t, arguments[1], laravelResourceOptionArgument(arguments, 1))
	assert.Nil(t, laravelResourceOptionArgument(arguments, 2))
	assert.Nil(t, laravelResourceOptionArgument(arguments, -1))
}

func TestApplyLaravelResourceArray(t *testing.T) {
	arguments := callArguments(lexPHP([]byte(`resource('posts', PostController::class, [
        'except' => ['show'],
        'only' => ['index', 'show'],
        'shallow' => true,
        'ignored' => 'value',
    ])`)), 1)
	config := laravelResourceConfig{actions: defaultLaravelResourceActions("resource")}

	config = applyLaravelResourceArray(config, arguments[2])

	assert.Equal(t, selectedResourceActions([]string{"index"}), config.actions)
	assert.True(t, config.shallow)

	malformedItems := callArguments(lexPHP([]byte(`resource('posts', PostController::class, [
		'only',
		'except' => ['show'],
	])`)), 1)
	config = laravelResourceConfig{actions: defaultLaravelResourceActions("resource")}
	config = applyLaravelResourceArray(config, malformedItems[2])
	assert.NotContains(t, config.actions, "show")

	uppercaseKey := callArguments(lexPHP([]byte(`resource('posts', PostController::class, [
		'ONLY' => ['index'],
	])`)), 1)
	config = laravelResourceConfig{actions: defaultLaravelResourceActions("resource")}
	config = applyLaravelResourceArray(config, uppercaseKey[2])
	assert.Equal(t, defaultLaravelResourceActions("resource"), config.actions)

	original := laravelResourceConfig{actions: selectedResourceActions([]string{"show"})}
	assert.Equal(t, original, applyLaravelResourceArray(original, nil))
	assert.Equal(t, original, applyLaravelResourceArray(original, lexPHP([]byte(`'only' => ['index']`))))

	// A bareword key (not a quoted string) must not be mistaken for the
	// "only"/"except"/"shallow" option keys, even if its name matches.
	bareKey := callArguments(lexPHP([]byte(`resource('posts', PostController::class, [
		only => ['index'],
	])`)), 1)
	config = laravelResourceConfig{actions: defaultLaravelResourceActions("resource")}
	config = applyLaravelResourceArray(config, bareKey[2])
	assert.Equal(t, defaultLaravelResourceActions("resource"), config.actions)
}

func TestApplyLaravelResourceActionSelection(t *testing.T) {
	config := laravelResourceConfig{
		actions:       defaultLaravelResourceActions("resource"),
		onlyActions:   []string{"index", "show"},
		exceptActions: []string{"show"},
		hasOnly:       true,
	}

	selected := applyLaravelResourceActionSelection(config)

	assert.Equal(t, selectedResourceActions([]string{"index"}), selected.actions)
}

func TestResourceActionNames(t *testing.T) {
	arguments := callArguments(lexPHP([]byte(`only('SHOW', ['index', 'Store', $dynamic], $action)`)), 1)

	assert.Equal(t, []string{"SHOW", "index", "Store"}, resourceActionNames(arguments))
	assert.Nil(t, resourceActionNames(nil))
	assert.Nil(t, resourceActionNames(callArguments(lexPHP([]byte(`only([buildAction()])`)), 1)))
}

func TestSelectedResourceActions(t *testing.T) {
	assert.Equal(t, map[string]struct{}{
		"index": {},
		"show":  {},
	}, selectedResourceActions([]string{"index", "show", "index"}))
	assert.Empty(t, selectedResourceActions(nil))
}

func TestAddLaravelResource(t *testing.T) {
	routes := newRouteSet()
	config := laravelResourceConfig{
		actions: selectedResourceActions([]string{
			"index", "create", "store", "show", "edit", "update", "destroy", "unsupported",
		}),
	}

	addLaravelResource("/api", "photos", config, routes)

	assert.Equal(t, routeSet{
		"/api/photos":              {},
		"/api/photos/create":       {},
		"/api/photos/{photo}":      {},
		"/api/photos/{photo}/edit": {},
	}, routes)
}

func TestLaravelResourcePaths(t *testing.T) {
	tests := []struct {
		name       string
		resource   string
		config     laravelResourceConfig
		collection string
		member     string
	}{
		{name: "resource", resource: "photos", collection: "/photos", member: "/photos/{photo}"},
		{
			name:       "nested resource",
			resource:   "photos.comments",
			collection: "/photos/{photo}/comments",
			member:     "/photos/{photo}/comments/{comment}",
		},
		{
			name:       "shallow nested resource",
			resource:   "photos.comments",
			config:     laravelResourceConfig{shallow: true},
			collection: "/photos/{photo}/comments",
			member:     "/comments/{comment}",
		},
		{
			name:       "singleton",
			resource:   "profile",
			config:     laravelResourceConfig{singleton: true},
			collection: "/profile",
			member:     "/profile",
		},
		{
			name:       "nested singleton",
			resource:   "photos.thumbnail",
			config:     laravelResourceConfig{singleton: true},
			collection: "/photos/{photo}/thumbnail",
			member:     "/photos/{photo}/thumbnail",
		},
		{
			name:       "slash-prefixed resource",
			resource:   "admin/photos",
			collection: "/admin/photos",
			member:     "/admin/photos/{photo}",
		},
		{
			name:       "slash-prefixed nested resource",
			resource:   "admin/photos.comments",
			collection: "/admin/photos/{photo}/comments",
			member:     "/admin/photos/{photo}/comments/{comment}",
		},
		{
			name:       "slash-prefixed shallow nested resource",
			resource:   "admin/photos.comments",
			config:     laravelResourceConfig{shallow: true},
			collection: "/admin/photos/{photo}/comments",
			member:     "/admin/comments/{comment}",
		},
		{
			name:       "slash-prefixed singleton",
			resource:   "admin/profile",
			config:     laravelResourceConfig{singleton: true},
			collection: "/admin/profile",
			member:     "/admin/profile",
		},
		{name: "empty resource", resource: "/"},
		{name: "dot-only resource", resource: "./"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collection, member := laravelResourcePaths(test.resource, test.config)

			assert.Equal(t, test.collection, collection)
			assert.Equal(t, test.member, member)
		})
	}
}

func TestResourceParameter(t *testing.T) {
	tests := map[string]string{
		"users":      "{user}",
		"categories": "{category}",
		"blog-posts": "{blog_post}",
		"profile":    "{profile}",
	}

	for resource, want := range tests {
		assert.Equal(t, want, resourceParameter(resource), resource)
	}
}
