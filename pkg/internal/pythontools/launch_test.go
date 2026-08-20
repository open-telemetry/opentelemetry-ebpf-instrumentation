// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePythonLaunch(t *testing.T) {
	tests := []struct {
		name         string
		executable   string
		args         []string
		env          map[string]string
		target       string
		kind         targetKind
		searchPaths  []string
		fallbackName string
		fastAPIAuto  bool
	}{
		{name: "script", executable: "python3.14", args: []string{"/srv/orders.py"}, target: "/srv/orders.py", kind: targetFile},
		{name: "interpreter options", executable: "python", args: []string{"-I", "-W", "ignore", "orders.py"}, target: "orders.py", kind: targetFile},
		{name: "module", executable: "python", args: []string{"-m", "company.orders"}, target: "company.orders", kind: targetModule},
		{name: "module attached", executable: "python", args: []string{"-mcompany.orders"}, target: "company.orders", kind: targetModule},
		{name: "module uvicorn", executable: "python", args: []string{"-m", "uvicorn", "orders.api:app"}, target: "orders.api:app", kind: targetModule},
		{
			name:       "gunicorn",
			executable: "/venv/bin/gunicorn",
			args:       []string{"-w", "4", "-b", "0.0.0.0:8080", "orders.wsgi:application", "--timeout", "90"},
			target:     "orders.wsgi:application",
			kind:       targetModule,
		},
		{
			name:       "gunicorn environment and command line precedence",
			executable: "gunicorn",
			args:       []string{"--chdir", "/srv/orders", "--name", "cli-name", "orders.wsgi:application"},
			env: map[string]string{
				"GUNICORN_CMD_ARGS": `--chdir '/srv/default app' --pythonpath=/libs,/shared --name env-name`,
			},
			target:       "orders.wsgi:application",
			kind:         targetModule,
			searchPaths:  []string{"/srv/orders", "/libs", "/shared"},
			fallbackName: "cli-name",
		},
		{
			name:        "uvicorn environment",
			executable:  "uvicorn",
			env:         map[string]string{"UVICORN_APP": "orders.api:app", "UVICORN_APP_DIR": "/srv"},
			target:      "orders.api:app",
			kind:        targetModule,
			searchPaths: []string{"/srv"},
		},
		{name: "hypercorn", executable: "hypercorn", args: []string{"--bind", "0.0.0.0:8080", "orders.asgi:app"}, target: "orders.asgi:app", kind: targetModule},
		{name: "daphne", executable: "daphne", args: []string{"-b", "0.0.0.0", "orders.asgi:application"}, target: "orders.asgi:application", kind: targetModule},
		{name: "uwsgi module", executable: "uwsgi", args: []string{"--http", ":8080", "--module", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: targetModule},
		{name: "uwsgi file", executable: "uwsgi", args: []string{"--wsgi-file", "/srv/orders.py"}, target: "/srv/orders.py", kind: targetFile},
		{name: "waitress", executable: "waitress-serve", args: []string{"--listen", "*:8080", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: targetModule},
		{name: "flask command line wins", executable: "flask", args: []string{"--app", "orders.web:create_app", "run"}, env: map[string]string{"FLASK_APP": "other"}, target: "orders.web:create_app", kind: targetModule},
		{name: "fastapi path", executable: "fastapi", args: []string{"run", "src/orders/main.py", "--port", "8080"}, target: "src/orders/main.py", kind: targetFile},
		{name: "fastapi automatic", executable: "fastapi", args: []string{"run"}, fastAPIAuto: true},
		{name: "django settings", executable: "django-admin", args: []string{"runserver", "--settings=company.orders.settings.production"}, target: "company.orders.settings.production", kind: targetModule},
		{name: "manage settings", executable: "python", args: []string{"manage.py", "runserver", "--settings", "orders.settings"}, target: "orders.settings", kind: targetModule},
		{name: "manage fallback", executable: "python", args: []string{"manage.py", "runserver"}, target: "manage.py", kind: targetFile},
		{name: "celery", executable: "celery", args: []string{"-A", "company.orders.tasks", "worker"}, target: "company.orders.tasks", kind: targetModule},
		{name: "celery module", executable: "python", args: []string{"-m", "celery", "--app=orders.celery", "worker"}, target: "orders.celery", kind: targetModule},
		{name: "eval", executable: "python", args: []string{"-c", "serve()"}},
		{name: "stdin", executable: "python", args: []string{"-"}},
		{name: "standard library server", executable: "python", args: []string{"-m", "http.server", "8080"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launch := parsePythonLaunch(tt.executable, tt.args, tt.env)

			assert.Equal(t, tt.target, launch.target)
			assert.Equal(t, tt.kind, launch.targetKind)
			assert.Equal(t, tt.searchPaths, launch.searchPaths)
			assert.Equal(t, tt.fallbackName, launch.fallbackName)
			assert.Equal(t, tt.fastAPIAuto, launch.fastAPIAuto)
		})
	}
}

func TestTargetName(t *testing.T) {
	tests := map[string]string{
		"company.orders.api:app":                 "orders",
		"orders.wsgi:application":                "orders",
		"company.orders.settings.production":     "orders",
		"company.orders.tasks":                   "orders",
		"src/orders_service.py":                  "orders_service",
		"app.main:app":                           "",
		"main.py":                                "",
		"config.settings":                        "",
		"src/orders/__init__.py":                 "",
		"company.inventory.application:create()": "inventory",
	}
	for target, expected := range tests {
		t.Run(target, func(t *testing.T) {
			assert.Equal(t, expected, targetName(target))
		})
	}
}

func TestSplitShellFields(t *testing.T) {
	fields, ok := splitShellFields(`--chdir '/srv/orders api' --name="orders service" --workers 4`)

	assert.True(t, ok)
	assert.Equal(t, []string{"--chdir", "/srv/orders api", "--name=orders service", "--workers", "4"}, fields)

	_, ok = splitShellFields(`--chdir 'unterminated`)
	assert.False(t, ok)
}
