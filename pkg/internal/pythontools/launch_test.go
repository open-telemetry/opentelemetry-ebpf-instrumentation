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
		scriptDir    string
		fallbackName string
		fastAPIAuto  bool
		flaskAuto    bool
		pathConfig   pythonPathConfig
	}{
		{name: "script", executable: "python3.14", args: []string{"/srv/orders.py"}, target: "/srv/orders.py", kind: targetScriptPath},
		{name: "interpreter options", executable: "python", args: []string{"-I", "-W", "ignore", "orders.py"}, target: "orders.py", kind: targetScriptPath, pathConfig: pythonPathConfig{ignorePythonEnvironment: true, safePath: true}},
		{name: "module", executable: "python", args: []string{"-m", "company.orders"}, target: "company.orders", kind: targetRunnableModule},
		{name: "module attached", executable: "python", args: []string{"-mcompany.orders"}, target: "company.orders", kind: targetRunnableModule},
		{name: "dotted module beginning with launcher", executable: "python", args: []string{"-m", "celery.task"}, target: "celery.task", kind: targetRunnableModule},
		{name: "module suffix is not a file extension", executable: "python", args: []string{"-m", "celery.py"}, target: "celery.py", kind: targetRunnableModule},
		{name: "module launcher matching is case sensitive", executable: "python", args: []string{"-m", "Celery"}, target: "Celery", kind: targetRunnableModule},
		{name: "ignore environment", executable: "python", args: []string{"-E", "-m", "company.orders"}, target: "company.orders", kind: targetRunnableModule, pathConfig: pythonPathConfig{ignorePythonEnvironment: true}},
		{name: "safe path", executable: "python", args: []string{"-P", "-m", "company.orders"}, target: "company.orders", kind: targetRunnableModule, pathConfig: pythonPathConfig{safePath: true}},
		{name: "clustered module", executable: "python", args: []string{"-IPmcompany.orders"}, target: "company.orders", kind: targetRunnableModule, pathConfig: pythonPathConfig{ignorePythonEnvironment: true, safePath: true}},
		{name: "clustered eval", executable: "python", args: []string{"-Ic", "serve()", "orders.py"}},
		{name: "clustered x option", executable: "python", args: []string{"-IX", "dev", "-m", "company.orders"}, target: "company.orders", kind: targetRunnableModule, pathConfig: pythonPathConfig{ignorePythonEnvironment: true, safePath: true}},
		{name: "warning value looks isolated", executable: "python", args: []string{"-W", "-I", "-m", "company.orders"}, target: "company.orders", kind: targetRunnableModule},
		{name: "attached warning looks safe", executable: "python", args: []string{"-WignoreP", "-m", "company.orders"}, target: "company.orders", kind: targetRunnableModule},
		{name: "attached x option looks isolated", executable: "python", args: []string{"-XI", "-m", "company.orders"}, target: "company.orders", kind: targetRunnableModule},
		{name: "module argument looks isolated", executable: "python", args: []string{"-m", "company.orders", "-I"}, target: "company.orders", kind: targetRunnableModule},
		{name: "module uvicorn", executable: "python", args: []string{"-I", "-m", "uvicorn", "orders.api:app"}, target: "orders.api:app", kind: targetModule, searchPaths: []string{"."}, pathConfig: pythonPathConfig{ignorePythonEnvironment: true, safePath: true}},
		{name: "module gunicorn", executable: "python", args: []string{"-I", "-m", "gunicorn", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: targetModule, searchPaths: []string{"."}, pathConfig: pythonPathConfig{ignorePythonEnvironment: true, safePath: true}},
		{
			name:       "ignore environment keeps uvicorn environment",
			executable: "python",
			args:       []string{"-E", "-m", "uvicorn"},
			env: map[string]string{
				"UVICORN_APP":     "orders.api:app",
				"UVICORN_APP_DIR": "/srv",
			},
			target:      "orders.api:app",
			kind:        targetModule,
			searchPaths: []string{"/srv"},
			pathConfig:  pythonPathConfig{ignorePythonEnvironment: true},
		},
		{
			name:        "gunicorn",
			executable:  "/venv/bin/gunicorn",
			args:        []string{"-w", "4", "-b", "0.0.0.0:8080", "orders.wsgi:application", "--timeout", "90"},
			target:      "orders.wsgi:application",
			kind:        targetModule,
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
			kind:         targetModule,
			searchPaths:  []string{"/shared", "/libs", "/srv/orders"},
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
		{name: "hypercorn", executable: "hypercorn", args: []string{"--bind", "0.0.0.0:8080", "orders.asgi:app"}, target: "orders.asgi:app", kind: targetModule, searchPaths: []string{"."}},
		{name: "daphne", executable: "daphne", args: []string{"-b", "0.0.0.0", "orders.asgi:application"}, target: "orders.asgi:application", kind: targetModule, searchPaths: []string{"."}},
		{name: "uwsgi module", executable: "uwsgi", args: []string{"--http", ":8080", "--module", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: targetModule, searchPaths: []string{"."}},
		{name: "uwsgi wsgi alias", executable: "uwsgi", args: []string{"--wsgi", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: targetModule, searchPaths: []string{"."}},
		{name: "uwsgi short module", executable: "uwsgi", args: []string{"-worders.wsgi:application"}, target: "orders.wsgi:application", kind: targetModule, searchPaths: []string{"."}},
		{name: "uwsgi file", executable: "uwsgi", args: []string{"--wsgi-file", "/srv/orders.py"}, target: "/srv/orders.py", kind: targetFile, searchPaths: []string{"."}},
		{name: "uwsgi file alias", executable: "uwsgi", args: []string{"--file", "/srv/orders.py"}, target: "/srv/orders.py", kind: targetFile, searchPaths: []string{"."}},
		{name: "uwsgi repeated python paths", executable: "uwsgi", args: []string{"--module", "orders.wsgi:application", "--pythonpath", "/one", "--python-path=/two", "--pp", "/three"}, target: "orders.wsgi:application", kind: targetModule, searchPaths: []string{"/three", "/two", "/one", "."}},
		{name: "waitress", executable: "waitress-serve", args: []string{"--listen", "*:8080", "orders.wsgi:application"}, target: "orders.wsgi:application", kind: targetModule},
		{name: "flask command line wins", executable: "flask", args: []string{"--app", "orders.web:create_app", "run"}, env: map[string]string{"FLASK_APP": "other"}, target: "orders.web:create_app", kind: targetModule, searchPaths: []string{"."}},
		{name: "flask short app option", executable: "flask", args: []string{"-A", "orders.web:create_app", "run"}, target: "orders.web:create_app", kind: targetModule, searchPaths: []string{"."}},
		{name: "flask attached short app option", executable: "flask", args: []string{"-Aorders.web:create_app", "run"}, target: "orders.web:create_app", kind: targetModule, searchPaths: []string{"."}},
		{name: "flask automatic", executable: "flask", args: []string{"run"}, flaskAuto: true},
		{name: "fastapi path", executable: "fastapi", args: []string{"run", "src/orders/main.py", "--port", "8080"}, target: "src/orders/main.py", kind: targetFile},
		{name: "fastapi automatic", executable: "fastapi", args: []string{"run"}, fastAPIAuto: true},
		{name: "django settings", executable: "django-admin", args: []string{"runserver", "--settings=company.orders.settings.production"}, target: "company.orders.settings.production", kind: targetModule},
		{name: "django pythonpath", executable: "django-admin", args: []string{"--pythonpath", "/one", "runserver", "--pythonpath=/two", "--settings", "orders.settings"}, target: "orders.settings", kind: targetModule, searchPaths: []string{"/two"}},
		{name: "manage settings", executable: "python", args: []string{"/srv/orders/manage.py", "runserver", "--settings", "orders.settings"}, target: "orders.settings", kind: targetModule, scriptDir: "/srv/orders"},
		{name: "manage fallback", executable: "python", args: []string{"manage.py", "runserver"}, target: "manage.py", kind: targetScriptPath},
		{name: "celery", executable: "celery", args: []string{"-A", "company.orders.tasks", "worker"}, target: "company.orders.tasks", kind: targetModule},
		{name: "celery environment", executable: "celery", args: []string{"worker"}, env: map[string]string{"CELERY_APP": "company.orders"}, target: "company.orders", kind: targetModule},
		{name: "celery command line overrides environment", executable: "celery", args: []string{"--app", "company.invoices", "worker"}, env: map[string]string{"CELERY_APP": "company.orders"}, target: "company.invoices", kind: targetModule},
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
			assert.Equal(t, tt.scriptDir, launch.scriptDir)
			assert.Equal(t, tt.fallbackName, launch.fallbackName)
			assert.Equal(t, tt.fastAPIAuto, launch.fastAPIAuto)
			assert.Equal(t, tt.flaskAuto, launch.flaskAuto)
			assert.Equal(t, tt.pathConfig, launch.pathConfig)
		})
	}
}

func TestParseFastAPIEntrypoint(t *testing.T) {
	const application = "company.orders.api:app"
	tests := map[string][]string{
		"long option":           {"run", "--entrypoint", application},
		"attached long option":  {"run", "--entrypoint=" + application},
		"short option":          {"dev", "-e", application},
		"attached short option": {"dev", "-e" + application},
		"short cluster":         {"run", "-ve" + application},
		"short cluster value":   {"run", "-ve", application},
		"last option wins":      {"run", "--entrypoint", "other.api:app", "--entrypoint", application},
		"after flag":            {"run", "--proxy-headers", "--entrypoint", application},
		"after negative flag":   {"run", "--no-proxy-headers", "--entrypoint", application},
		"after global option":   {"--verbose", "run", "--entrypoint", application},
		"after negative global": {"--no-verbose", "run", "--entrypoint", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("fastapi", args, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
			assert.False(t, launch.fastAPIAuto)
		})
	}

	for name, args := range map[string][]string{
		"missing value":               {"run", "--entrypoint"},
		"empty value":                 {"run", "--entrypoint="},
		"with path":                   {"run", "main.py", "--entrypoint", application},
		"with app option":             {"run", "--app", "api", "--entrypoint", application},
		"app without path":            {"run", "--app", "api"},
		"invalid import string":       {"run", "--entrypoint", "company.orders.api"},
		"factory call":                {"run", "--entrypoint", "company.orders.api:create_app()"},
		"padded entrypoint":           {"run", "--entrypoint", " " + application + " "},
		"unknown option":              {"run", "--future-option", "env:prod", "main.py"},
		"unknown attached":            {"run", "--future-option=env:prod", "main.py"},
		"unknown short":               {"run", "-Z", "env:prod", "main.py"},
		"unknown after path":          {"run", "main.py", "--future-option"},
		"value on flag":               {"run", "--proxy-headers=true", "main.py"},
		"multiple paths":              {"run", "env:prod", "main.py"},
		"unknown before command":      {"--future-option", "run", "main.py"},
		"global option after command": {"run", "--no-verbose", "main.py"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, pythonLaunch{}, parsePythonLaunch("fastapi", args, nil))
		})
	}

	for name, args := range map[string][]string{
		"long entrypoint is another option value":  {"run", "--root-path", "--entrypoint=" + application},
		"short entrypoint is another option value": {"run", "--root-path", "-e" + application},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, pythonLaunch{fastAPIAuto: true}, parsePythonLaunch("fastapi", args, nil))
		})
	}
}

func TestParseGunicornOptions(t *testing.T) {
	const application = "orders.wsgi:application"

	optionsWithValues := []string{
		"-c", "--config", "-b", "--bind", "--backlog", "-w", "--workers", "-k", "--worker-class", "--threads",
		"--worker-connections", "--max-requests", "--max-requests-jitter", "-t", "--timeout", "--graceful-timeout",
		"--keep-alive", "--limit-request-line", "--limit-request-fields", "--limit-request-field_size",
		"--reload-engine", "--reload-extra-file", "--chdir", "-e", "--env", "-p", "--pid", "--worker-tmp-dir",
		"-u", "--user", "-g", "--group", "-m", "--umask", "--forwarded-allow-ips", "--access-logfile",
		"--access-logformat", "--error-logfile", "--log-file", "--log-level", "--logger-class", "--log-config",
		"--log-config-json", "--log-syslog-to", "--log-syslog-prefix", "--log-syslog-facility", "--statsd-host",
		"--dogstatsd-tags", "--statsd-prefix", "-n", "--name", "--pythonpath", "--paste", "--paster",
		"--proxy-allow-from", "--protocol", "--uwsgi-allow-from", "--keyfile", "--certfile", "--ssl-version",
		"--cert-reqs", "--ca-certs", "--ciphers", "--http-protocols", "--http2-cleartext",
		"--http2-max-concurrent-streams", "--http2-initial-window-size", "--http2-max-frame-size",
		"--http2-max-header-list-size", "--paste-global", "--forwarder-headers", "--header-map", "--asgi-loop",
		"--asgi-lifespan", "--asgi-disconnect-grace-period", "--http-parser", "--root-path", "--dirty-app",
		"--dirty-workers", "--dirty-timeout", "--dirty-threads", "--dirty-graceful-timeout", "--control-socket",
		"--control-socket-mode",
	}
	assert.Equal(t, optionSet(optionsWithValues...), gunicornOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("gunicorn", []string{option, "env:prod", application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}

	optionsWithoutValues := []string{
		"--reload", "--spew", "--check-config", "--print-config", "--preload", "--no-sendfile", "--reuse-port",
		"-D", "--daemon", "--initgroups", "--disable-redirect-access-to-syslog", "--capture-output",
		"--log-syslog", "-R", "--enable-stdio-inheritance", "--enable-backlog-metric", "--suppress-ragged-eofs",
		"--do-handshake-on-connect", "--permit-obsolete-folding", "--strip-header-spaces",
		"--permit-unconventional-http-method", "--permit-unconventional-http-version", "--casefold-http-method",
		"--no-control-socket", "-h", "--help", "-v", "--version", "--proxy-protocol",
	}
	assert.Equal(t, optionSet(optionsWithoutValues...), gunicornOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("gunicorn", []string{option, application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseGunicornApplicationForms(t *testing.T) {
	tests := map[string]string{
		"default application object":  "company.orders.wsgi",
		"explicit application object": "company.orders.wsgi:application",
		"factory application object":  "company.orders.wsgi:create_app()",
	}
	for name, application := range tests {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("gunicorn", []string{"--workers", "4", application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseGunicornFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "long option", args: []string{"--future-option", "env:prod", application}},
		{name: "attached long option", args: []string{"--future-option=env:prod", application}},
		{name: "short option", args: []string{"-Z", "env:prod", application}},
		{name: "short option cluster", args: []string{"-DZ", application}},
		{name: "after application", args: []string{application, "--future-option", "env:prod"}},
		{name: "before known flag", args: []string{"--future-option", "--capture-output", application}},
		{
			name: "environment option",
			args: []string{application},
			env:  map[string]string{"GUNICORN_CMD_ARGS": "--future-option env:prod"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, pythonLaunch{}, parsePythonLaunch("gunicorn", tt.args, tt.env))
		})
	}
}

func TestParseGunicornAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := map[string][]string{
		"attached short value":    {"-w4", application},
		"short value with equals": {"-w=4", application},
		"attached long value":     {"--workers=4", application},
		"attached tags":           {"--dogstatsd-tags=env:prod", application},
		"short flag cluster":      {"-DR", application},
		"after terminator":        {"--", application, "--future-option", "env:prod"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("gunicorn", args, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}

	launch := parsePythonLaunch("gunicorn", []string{"main:app", "--", "--name", "wrong"}, nil)
	assert.Empty(t, launch.fallbackName)

	for _, option := range []string{"-Dnorders", "-Dn=orders"} {
		launch := parsePythonLaunch("gunicorn", []string{option, "main:app"}, nil)
		assert.Equal(t, "orders", launch.fallbackName)
	}
}

func TestParseGunicornProxyProtocolOption(t *testing.T) {
	const application = "orders.wsgi:application"

	tests := map[string][]string{
		"separated off value":    {"--proxy-protocol", "off", application},
		"separated v1 value":     {"--proxy-protocol", "v1", application},
		"separated v2 value":     {"--proxy-protocol", "v2", application},
		"separated auto value":   {"--proxy-protocol", "auto", application},
		"attached value":         {"--proxy-protocol=v1", application},
		"legacy bare flag":       {"--proxy-protocol", application},
		"bare before module app": {"--proxy-protocol", "company.orders.wsgi"},
		"bare before an option":  {"--proxy-protocol", "--dogstatsd-tags", "env:prod", application},
		"bare after application": {application, "--proxy-protocol"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("gunicorn", args, nil)

			expected := application
			if name == "bare before module app" {
				expected = "company.orders.wsgi"
			}
			assert.Equal(t, expected, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}

	assert.Equal(t, pythonLaunch{}, parsePythonLaunch("gunicorn", []string{"--proxy-protocol=invalid", application}, nil))
}

func TestParseUvicornOptions(t *testing.T) {
	const application = "orders.api:app"
	optionsWithValues := []string{
		"--host", "--port", "--uds", "--fd", "--reload-dir", "--reload-include", "--reload-exclude",
		"--reload-delay", "--workers", "--loop", "--http", "--ws", "--ws-max-size", "--ws-max-queue",
		"--ws-ping-interval", "--ws-ping-timeout", "--ws-per-message-deflate", "--lifespan", "--interface",
		"--env-file", "--log-config", "--log-level", "--forwarded-allow-ips", "--root-path",
		"--limit-concurrency", "--backlog", "--limit-max-requests", "--limit-max-requests-jitter",
		"--timeout-keep-alive", "--timeout-graceful-shutdown", "--timeout-worker-healthcheck", "--ssl-keyfile",
		"--ssl-certfile", "--ssl-keyfile-password", "--ssl-version", "--ssl-cert-reqs", "--ssl-ca-certs",
		"--ssl-ciphers", "--header", "--app-dir", "--h11-max-incomplete-event-size",
	}
	assert.Equal(t, optionSet(optionsWithValues...), uvicornOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("uvicorn", []string{option, "env:prod", application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}

	optionsWithoutValues := []string{
		"--reload", "--access-log", "--no-access-log", "--use-colors", "--no-use-colors", "--proxy-headers",
		"--no-proxy-headers", "--server-header", "--no-server-header", "--date-header", "--no-date-header",
		"--version", "--reset-contextvars", "--factory", "--help",
	}
	assert.Equal(t, optionSet(optionsWithoutValues...), uvicornOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("uvicorn", []string{option, application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseUvicornFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.api:app"
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "long option", args: []string{"--future-option", "env:prod", application}},
		{name: "attached long option", args: []string{"--future-option=env:prod", application}},
		{name: "short option", args: []string{"-Z", "env:prod", application}},
		{name: "after application", args: []string{application, "--future-option", "env:prod"}},
		{name: "value on flag", args: []string{"--reload=true", application}},
		{name: "missing value", args: []string{application, "--workers"}},
		{
			name: "environment application",
			args: []string{"--future-option", "env:prod"},
			env:  map[string]string{"UVICORN_APP": application},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, pythonLaunch{}, parsePythonLaunch("uvicorn", tt.args, tt.env))
		})
	}
}

func TestParseUvicornAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.api:app"
	tests := []struct {
		name        string
		args        []string
		env         map[string]string
		searchPaths []string
	}{
		{name: "attached value", args: []string{"--host=0.0.0.0", application}, searchPaths: []string{"."}},
		{name: "option after application", args: []string{application, "--port", "8000"}, searchPaths: []string{"."}},
		{name: "after terminator", args: []string{"--", application, "--future-option", "env:prod"}, searchPaths: []string{"."}},
		{name: "separated app directory", args: []string{"--app-dir", "/srv", application}, searchPaths: []string{"/srv"}},
		{name: "attached app directory", args: []string{"--app-dir=/srv", application}, searchPaths: []string{"/srv"}},
		{
			name:        "app directory after terminator",
			args:        []string{application, "--", "--app-dir", "/wrong"},
			env:         map[string]string{"UVICORN_APP_DIR": "/srv"},
			searchPaths: []string{"/srv"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launch := parsePythonLaunch("uvicorn", tt.args, tt.env)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
			assert.Equal(t, tt.searchPaths, launch.searchPaths)
		})
	}
}

func TestParseHypercornOptions(t *testing.T) {
	const application = "orders.asgi:app"
	optionsWithValues := []string{
		"--access-log", "--access-logfile", "--access-logformat", "--backlog", "-b", "--bind", "--ca-certs",
		"--certfile", "--cert-reqs", "--ciphers", "-c", "--config", "--error-log", "--error-logfile", "--log-file",
		"--graceful-timeout", "--read-timeout", "--max-requests", "--max-requests-jitter", "-g", "--group", "-k",
		"--worker-class", "--keep-alive", "--keyfile", "--keyfile-password", "--insecure-bind", "--log-config",
		"--log-level", "-p", "--pid", "--quic-bind", "--root-path", "--server-name", "--statsd-host",
		"--statsd-prefix", "-m", "--umask", "-u", "--user", "--verify-mode", "--websocket-ping-interval", "-w",
		"--workers",
	}
	assert.Equal(t, optionSet(optionsWithValues...), hypercornOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("hypercorn", []string{option, "env:prod", application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}

	optionsWithoutValues := []string{"-D", "--daemon", "--debug", "--reload", "-h", "--help"}
	assert.Equal(t, optionSet(optionsWithoutValues...), hypercornOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("hypercorn", []string{option, application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseHypercornApplicationForms(t *testing.T) {
	tests := []struct {
		name        string
		application string
		target      string
		kind        targetKind
	}{
		{name: "default app object", application: "company.orders.api", target: "company.orders.api", kind: targetModule},
		{name: "explicit app object", application: "company.orders.api:app", target: "company.orders.api:app", kind: targetModule},
		{name: "file app", application: "src/api.py:app", target: "src/api.py:app", kind: targetFile},
		{name: "asgi mode", application: "asgi:company.orders.api:app", target: "company.orders.api:app", kind: targetModule},
		{name: "wsgi file mode", application: "wsgi:src/api.py:app", target: "src/api.py:app", kind: targetFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launch := parsePythonLaunch("hypercorn", []string{"--workers", "4", tt.application}, nil)

			assert.Equal(t, tt.target, launch.target)
			assert.Equal(t, tt.kind, launch.targetKind)
			assert.Equal(t, []string{"."}, launch.searchPaths)
		})
	}
}

func TestParseHypercornFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.asgi:app"
	tests := map[string][]string{
		"long option":                {"--future-option", "env:prod", application},
		"attached long option":       {"--future-option=env:prod", application},
		"short option":               {"-Z", "env:prod", application},
		"short option cluster":       {"-DZ", application},
		"after application":          {application, "--future-option", "env:prod"},
		"value on flag":              {"--reload=true", application},
		"missing value":              {application, "--workers"},
		"unknown option as value":    {"--access-logfile", "--future-option", "env:prod", application},
		"invalid cipher option":      {"--cipher", "env:prod", application},
		"unsupported paste option":   {"--paste", "config:prod", application},
		"unsupported version option": {"--version", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, pythonLaunch{}, parsePythonLaunch("hypercorn", args, nil))
		})
	}
}

func TestParseHypercornAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.asgi:app"
	tests := map[string][]string{
		"stdout access log":        {"--access-logfile", "-", application},
		"attached stdout log":      {"--access-logfile=-", application},
		"python config":            {"--config", "python:settings", application},
		"attached python config":   {"--config=python:settings", application},
		"attached long value":      {"--workers=4", application},
		"attached short value":     {"-w4", application},
		"short value with equals":  {"-w=4", application},
		"short option cluster":     {"-Dw4", application},
		"negative long value":      {"--read-timeout", "-1", application},
		"negative short value":     {"-w", "-1", application},
		"option after application": {application, "--access-logfile", "-"},
		"after terminator":         {"--", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("hypercorn", args, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseDaphneOptions(t *testing.T) {
	const application = "orders.asgi:application"
	optionsWithValues := []string{
		"-p", "--port", "-b", "--bind", "--websocket_timeout", "--websocket_connect_timeout", "-u",
		"--unix-socket", "--fd", "-e", "--endpoint", "-v", "--verbosity", "-t", "--http-timeout",
		"--access-log", "--log-fmt", "--ping-interval", "--ping-timeout", "--websocket-max-message-size",
		"--websocket-max-frame-size", "--application-close-timeout", "--root-path", "--proxy-headers-host",
		"--proxy-headers-port", "-s", "--server-name",
	}
	assert.Equal(t, optionSet(optionsWithValues...), daphneOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("daphne", []string{option, "env:prod", application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}

	optionsWithoutValues := []string{"--proxy-headers", "--no-server-name", "-h", "--help"}
	assert.Equal(t, optionSet(optionsWithoutValues...), daphneOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("daphne", []string{option, application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseDaphneFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.asgi:application"
	tests := map[string][]string{
		"long option":               {"--future-option", "env:prod", application},
		"attached long option":      {"--future-option=env:prod", application},
		"short option":              {"-Z", "env:prod", application},
		"short option cluster":      {"-hZ", application},
		"after application":         {application, "--future-option", "env:prod"},
		"value on flag":             {"--proxy-headers=true", application},
		"missing value":             {application, "--port"},
		"unknown option as value":   {"--access-log", "--future-option", "env:prod", application},
		"removed proxy header name": {"--proxy-forwarded-address-header", "X-Forwarded-For", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, pythonLaunch{}, parsePythonLaunch("daphne", args, nil))
		})
	}
}

func TestParseDaphneAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.asgi:application"
	tests := map[string][]string{
		"stdout access log":        {"--access-log", "-", application},
		"attached stdout log":      {"--access-log=-", application},
		"attached long value":      {"--port=8000", application},
		"attached short value":     {"-p8000", application},
		"short value with equals":  {"-p=8000", application},
		"negative timeout":         {"--websocket_timeout", "-1", application},
		"option after application": {application, "--ping-interval", "30"},
		"after terminator":         {"--", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("daphne", args, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseWaitressOptions(t *testing.T) {
	const application = "orders.wsgi:application"
	optionsWithValues := []string{
		"--host", "--port", "--listen", "--threads", "--trusted-proxy", "--trusted-proxy-count",
		"--trusted-proxy-headers", "--url-scheme", "--url-prefix", "--backlog", "--recv-bytes",
		"--send-bytes", "--outbuf-overflow", "--outbuf-high-watermark", "--inbuf-overflow",
		"--connection-limit", "--cleanup-interval", "--channel-timeout", "--max-request-header-size",
		"--max-request-body-size", "--ident", "--asyncore-loop-timeout", "--unix-socket",
		"--unix-socket-perms", "--sockets", "--channel-request-lookahead", "--server-name", "--app",
	}
	assert.Equal(t, optionSet(optionsWithValues...), waitressOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			args := []string{option, "env:prod", application}
			if option == "--app" {
				args = []string{option, application}
			}
			launch := parsePythonLaunch("waitress-serve", args, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}

	optionsWithoutValues := []string{
		"--help", "--call", "--ipv4", "--no-ipv4", "--ipv6", "--no-ipv6",
		"--log-untrusted-proxy-headers", "--no-log-untrusted-proxy-headers",
		"--clear-untrusted-proxy-headers", "--no-clear-untrusted-proxy-headers", "--log-socket-errors",
		"--no-log-socket-errors", "--expose-tracebacks", "--no-expose-tracebacks", "--asyncore-use-poll",
		"--no-asyncore-use-poll",
	}
	assert.Equal(t, optionSet(optionsWithoutValues...), waitressOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := parsePythonLaunch("waitress-serve", []string{option, application}, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseWaitressFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := map[string][]string{
		"long option":                 {"--future-option", "env:prod", application},
		"attached long option":        {"--future-option=env:prod", application},
		"short option":                {"-Z", "env:prod", application},
		"after application":           {application, "--future-option", "env:prod"},
		"known option after app":      {application, "--threads", "4"},
		"value on flag":               {"--asyncore-use-poll=true", application},
		"missing value":               {"--threads"},
		"unknown option as value":     {"--ident", "--future-option", "env:prod", application},
		"multiple applications":       {application, "other.wsgi:application"},
		"explicit and positional app": {"--app", application, "other.wsgi:application"},
		"abbreviated option":          {"--thre=4", application},
		"invalid adjustment option":   {"--adj", "env:prod", application},
		"unsupported version option":  {"--version", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, pythonLaunch{}, parsePythonLaunch("waitress-serve", args, nil))
		})
	}
}

func TestParseWaitressAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := map[string][]string{
		"separated value":           {"--threads", "4", application},
		"attached value":            {"--threads=4", application},
		"negative value":            {"--asyncore-loop-timeout", "-1", application},
		"lone dash value":           {"--ident", "-", application},
		"attached dashed value":     {"--ident=--private", application},
		"repeated option":           {"--listen", "*:8000", "--listen=[::1]:8000", application},
		"explicit application":      {"--app", application},
		"attached application":      {"--app=" + application},
		"call application":          {"--call", application},
		"option after explicit app": {"--app", application, "--threads", "4"},
		"after terminator":          {"--", application},
		"negative boolean":          {"--no-expose-tracebacks", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("waitress-serve", args, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetModule, launch.targetKind)
		})
	}
}

func TestParseWaitressDottedApplication(t *testing.T) {
	const application = "company.orders.wsgi.create_app"
	for name, args := range map[string][]string{
		"positional":   {"--call", application},
		"explicit app": {"--call", "--app=" + application},
	} {
		t.Run(name, func(t *testing.T) {
			launch := parsePythonLaunch("waitress-serve", args, nil)

			assert.Equal(t, application, launch.target)
			assert.Equal(t, targetDottedReference, launch.targetKind)
		})
	}

	assert.Equal(t, pythonLaunch{}, parsePythonLaunch("waitress-serve", []string{
		"company.orders.wsgi:create_app()",
	}, nil))
	assert.Equal(t, pythonLaunch{}, parsePythonLaunch("waitress-serve", []string{
		" company.orders.wsgi:app ",
	}, nil))
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
