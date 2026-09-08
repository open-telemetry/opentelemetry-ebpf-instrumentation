// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"
)

func TestParsePythonLaunch(t *testing.T) {
	tests := []struct {
		name         string
		executable   string
		args         []string
		env          map[string]string
		target       string
		kind         frameworks.TargetKind
		searchPaths  []string
		scriptDir    string
		fallbackName string
		fastAPIAuto  bool
		flaskAuto    bool
		pathConfig   frameworks.PythonPathConfig
	}{
		{name: "script", executable: "python3.14", args: []string{"/srv/orders.py"}, target: "/srv/orders.py", kind: frameworks.TargetScriptPath},
		{name: "interpreter options", executable: "python", args: []string{"-I", "-W", "ignore", "orders.py"}, target: "orders.py", kind: frameworks.TargetScriptPath, pathConfig: frameworks.PythonPathConfig{IgnorePythonEnvironment: true, SafePath: true}},
		{name: "module", executable: "python", args: []string{"-m", "company.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule},
		{name: "module attached", executable: "python", args: []string{"-mcompany.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule},
		{name: "dotted module beginning with launcher", executable: "python", args: []string{"-m", "celery.task"}, target: "celery.task", kind: frameworks.TargetRunnableModule},
		{name: "module suffix is not a file extension", executable: "python", args: []string{"-m", "celery.py"}, target: "celery.py", kind: frameworks.TargetRunnableModule},
		{name: "module launcher matching is case sensitive", executable: "python", args: []string{"-m", "Celery"}, target: "Celery", kind: frameworks.TargetRunnableModule},
		{name: "ignore environment", executable: "python", args: []string{"-E", "-m", "company.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule, pathConfig: frameworks.PythonPathConfig{IgnorePythonEnvironment: true}},
		{name: "safe path", executable: "python", args: []string{"-P", "-m", "company.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule, pathConfig: frameworks.PythonPathConfig{SafePath: true}},
		{name: "clustered module", executable: "python", args: []string{"-IPmcompany.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule, pathConfig: frameworks.PythonPathConfig{IgnorePythonEnvironment: true, SafePath: true}},
		{name: "clustered eval", executable: "python", args: []string{"-Ic", "serve()", "orders.py"}},
		{name: "clustered x option", executable: "python", args: []string{"-IX", "dev", "-m", "company.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule, pathConfig: frameworks.PythonPathConfig{IgnorePythonEnvironment: true, SafePath: true}},
		{name: "warning value looks isolated", executable: "python", args: []string{"-W", "-I", "-m", "company.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule},
		{name: "attached warning looks safe", executable: "python", args: []string{"-WignoreP", "-m", "company.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule},
		{name: "attached x option looks isolated", executable: "python", args: []string{"-XI", "-m", "company.orders"}, target: "company.orders", kind: frameworks.TargetRunnableModule},
		{name: "module argument looks isolated", executable: "python", args: []string{"-m", "company.orders", "-I"}, target: "company.orders", kind: frameworks.TargetRunnableModule},
		{name: "module uvicorn", executable: "python", args: []string{"-I", "-m", "uvicorn", "orders.api:app"}, target: "orders.api:app", kind: frameworks.TargetModule, searchPaths: []string{"."}, pathConfig: frameworks.PythonPathConfig{IgnorePythonEnvironment: true, SafePath: true}},
		{name: "module gunicorn", executable: "python", args: []string{"-I", "-m", "gunicorn", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: frameworks.TargetModule, searchPaths: []string{"."}, pathConfig: frameworks.PythonPathConfig{IgnorePythonEnvironment: true, SafePath: true}},
		{
			name:       "ignore environment keeps uvicorn environment",
			executable: "python",
			args:       []string{"-E", "-m", "uvicorn"},
			env: map[string]string{
				"UVICORN_APP":     "orders.api:app",
				"UVICORN_APP_DIR": "/srv",
			},
			target:      "orders.api:app",
			kind:        frameworks.TargetModule,
			searchPaths: []string{"/srv"},
			pathConfig:  frameworks.PythonPathConfig{IgnorePythonEnvironment: true},
		},
		{
			name:        "gunicorn",
			executable:  "/venv/bin/gunicorn",
			args:        []string{"-w", "4", "-b", "0.0.0.0:8080", "orders.wsgi:application", "--timeout", "90"},
			target:      "orders.wsgi:application",
			kind:        frameworks.TargetModule,
			searchPaths: []string{"."},
		},
		{
			name:       "gunicorn environment and command line precedence",
			executable: "gunicorn",
			args:       []string{"--chdir", "/srv/orders", "--name", "cli-name", "orders.wsgi:application"},
			env: map[string]string{
				"GUNICORN_CMD_ARGS": `--chdir '/srv/default app' --pythonpath=/libs,/shared --name env-name`,
			},
			target:       "orders.wsgi:application",
			kind:         frameworks.TargetModule,
			searchPaths:  []string{"/shared", "/libs", "/srv/orders"},
			fallbackName: "cli-name",
		},
		{
			name:        "uvicorn environment",
			executable:  "uvicorn",
			env:         map[string]string{"UVICORN_APP": "orders.api:app", "UVICORN_APP_DIR": "/srv"},
			target:      "orders.api:app",
			kind:        frameworks.TargetModule,
			searchPaths: []string{"/srv"},
		},
		{name: "hypercorn", executable: "hypercorn", args: []string{"--bind", "0.0.0.0:8080", "orders.asgi:app"}, target: "orders.asgi:app", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "daphne", executable: "daphne", args: []string{"-b", "0.0.0.0", "orders.asgi:application"}, target: "orders.asgi:application", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "uwsgi module", executable: "uwsgi", args: []string{"--http", ":8080", "--module", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "uwsgi wsgi alias", executable: "uwsgi", args: []string{"--wsgi", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "uwsgi short module", executable: "uwsgi", args: []string{"-worders.wsgi:application"}, target: "orders.wsgi:application", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "uwsgi file", executable: "uwsgi", args: []string{"--wsgi-file", "/srv/orders.py"}, target: "/srv/orders.py", kind: frameworks.TargetFile, searchPaths: []string{"."}},
		{name: "uwsgi file alias", executable: "uwsgi", args: []string{"--file", "/srv/orders.py"}, target: "/srv/orders.py", kind: frameworks.TargetFile, searchPaths: []string{"."}},
		{name: "uwsgi repeated python paths", executable: "uwsgi", args: []string{"--module", "orders.wsgi:application", "--pythonpath", "/one", "--python-path=/two", "--pp", "/three"}, target: "orders.wsgi:application", kind: frameworks.TargetModule, searchPaths: []string{"/three", "/two", "/one", "."}},
		{name: "waitress", executable: "waitress-serve", args: []string{"--listen", "*:8080", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: frameworks.TargetModule},
		{name: "flask command line wins", executable: "flask", args: []string{"--app", "orders.web:create_app", "run"}, env: map[string]string{"FLASK_APP": "other"}, target: "orders.web:create_app", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "flask short app option", executable: "flask", args: []string{"-A", "orders.web:create_app", "run"}, target: "orders.web:create_app", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "flask attached short app option", executable: "flask", args: []string{"-Aorders.web:create_app", "run"}, target: "orders.web:create_app", kind: frameworks.TargetModule, searchPaths: []string{"."}},
		{name: "flask automatic", executable: "flask", args: []string{"run"}, flaskAuto: true},
		{name: "fastapi path", executable: "fastapi", args: []string{"run", "src/orders/main.py", "--port", "8080"}, target: "src/orders/main.py", kind: frameworks.TargetFile},
		{name: "fastapi automatic", executable: "fastapi", args: []string{"run"}, fastAPIAuto: true},
		{name: "django settings", executable: "django-admin", args: []string{"runserver", "--settings=company.orders.settings.production"}, target: "company.orders.settings.production", kind: frameworks.TargetModule},
		{name: "django pythonpath", executable: "django-admin", args: []string{"--pythonpath", "/one", "runserver", "--pythonpath=/two", "--settings", "orders.settings"}, target: "orders.settings", kind: frameworks.TargetModule, searchPaths: []string{"/two"}},
		{name: "manage settings", executable: "python", args: []string{"/srv/orders/manage.py", "runserver", "--settings", "orders.settings"}, target: "orders.settings", kind: frameworks.TargetModule, scriptDir: "/srv/orders"},
		{name: "manage fallback", executable: "python", args: []string{"manage.py", "runserver"}, target: "manage.py", kind: frameworks.TargetScriptPath},
		{name: "celery", executable: "celery", args: []string{"-A", "company.orders.tasks", "worker"}, target: "company.orders.tasks", kind: frameworks.TargetModule},
		{name: "celery environment", executable: "celery", args: []string{"worker"}, env: map[string]string{"CELERY_APP": "company.orders"}, target: "company.orders", kind: frameworks.TargetModule},
		{name: "celery command line overrides environment", executable: "celery", args: []string{"--app", "company.invoices", "worker"}, env: map[string]string{"CELERY_APP": "company.orders"}, target: "company.invoices", kind: frameworks.TargetModule},
		{name: "celery module", executable: "python", args: []string{"-m", "celery", "--app=orders.celery", "worker"}, target: "orders.celery", kind: frameworks.TargetModule},
		{name: "eval", executable: "python", args: []string{"-c", "serve()"}},
		{name: "stdin", executable: "python", args: []string{"-"}},
		{name: "standard library server", executable: "python", args: []string{"-m", "http.server", "8080"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launch := parsePythonLaunch(tt.executable, tt.args, tt.env)

			assert.Equal(t, tt.target, launch.Target)
			assert.Equal(t, tt.kind, launch.TargetKind)
			assert.Equal(t, tt.searchPaths, launch.SearchPaths)
			assert.Equal(t, tt.scriptDir, launch.ScriptDir)
			assert.Equal(t, tt.fallbackName, launch.FallbackName)
			assert.Equal(t, tt.fastAPIAuto, launch.FastAPIAuto)
			assert.Equal(t, tt.flaskAuto, launch.FlaskAuto)
			assert.Equal(t, tt.pathConfig, launch.PathConfig)
		})
	}
}
