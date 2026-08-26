// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"path/filepath"
	"strings"
	"unicode"
)

type targetKind uint8

const (
	targetNone targetKind = iota
	targetFile
	targetScriptPath
	targetModule
	targetRunnableModule
	targetDottedReference
)

type pythonLaunch struct {
	target       string
	targetKind   targetKind
	searchPaths  []string
	fallbackName string
	fastAPIAuto  bool
	pathConfig   pythonPathConfig
}

type pythonPathConfig struct {
	ignorePythonEnvironment bool
	safePath                bool
}

const interpreterOptionsWithoutValues = "bBdEhiIOPqRsStuvVx?"

var genericModuleNames = map[string]struct{}{
	"api":         {},
	"app":         {},
	"application": {},
	"asgi":        {},
	"celery":      {},
	"cli":         {},
	"conf":        {},
	"config":      {},
	"entrypoint":  {},
	"index":       {},
	"main":        {},
	"manage":      {},
	"models":      {},
	"project":     {},
	"routes":      {},
	"run":         {},
	"runserver":   {},
	"server":      {},
	"service":     {},
	"settings":    {},
	"src":         {},
	"start":       {},
	"tasks":       {},
	"urls":        {},
	"views":       {},
	"web":         {},
	"worker":      {},
	"wsgi":        {},
}

var nonApplicationModules = map[string]struct{}{
	"ensurepip":   {},
	"http.server": {},
	"idlelib":     {},
	"pip":         {},
	"pydoc":       {},
	"pytest":      {},
	"unittest":    {},
	"venv":        {},
}

func parsePythonLaunch(executable string, args []string, env map[string]string) pythonLaunch {
	command := commandName(executable)
	if isPythonInterpreter(command) {
		return parseInterpreterLaunch(args, env)
	}
	if launch, ok := parseLauncher(command, args, env); ok {
		return launch
	}
	return pythonLaunch{}
}

func parseInterpreterLaunch(args []string, env map[string]string) pythonLaunch {
	pathConfig := pythonPathConfig{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			if i+1 < len(args) {
				return pathConfig.apply(launchForScript(args[i+1], args[i+2:], env))
			}
			return pythonLaunch{}
		case arg == "-":
			return pythonLaunch{}
		case arg == "--check-hash-based-pycs":
			i++
			continue
		case strings.HasPrefix(arg, "--"):
			continue
		case strings.HasPrefix(arg, "-"):
			if launch, done := parseInterpreterShortOptions(arg[1:], args, &i, env, &pathConfig); done {
				return pathConfig.apply(launch)
			}
		default:
			return pathConfig.apply(launchForScript(arg, args[i+1:], env))
		}
	}
	return pythonLaunch{}
}

func parseInterpreterShortOptions(
	options string,
	args []string,
	index *int,
	env map[string]string,
	pathConfig *pythonPathConfig,
) (pythonLaunch, bool) {
	for optionIndex := 0; optionIndex < len(options); optionIndex++ {
		option := options[optionIndex]
		switch option {
		case 'E':
			pathConfig.ignorePythonEnvironment = true
		case 'I':
			pathConfig.ignorePythonEnvironment = true
			pathConfig.safePath = true
		case 'P':
			pathConfig.safePath = true
		case 'c':
			return pythonLaunch{}, true
		case 'm':
			module := options[optionIndex+1:]
			if module == "" {
				(*index)++
				if *index >= len(args) {
					return pythonLaunch{}, true
				}
				module = args[*index]
			}
			return launchForModule(module, args[*index+1:], env), true
		case 'W', 'X':
			if optionIndex+1 == len(options) {
				(*index)++
				if *index >= len(args) {
					return pythonLaunch{}, true
				}
			}
			return pythonLaunch{}, false
		default:
			if !strings.ContainsRune(interpreterOptionsWithoutValues, rune(option)) {
				return pythonLaunch{}, true
			}
		}
	}
	return pythonLaunch{}, false
}

func (config pythonPathConfig) apply(launch pythonLaunch) pythonLaunch {
	if launch.targetKind == targetNone && launch.target == "" && launch.fallbackName == "" &&
		!launch.fastAPIAuto && len(launch.searchPaths) == 0 {
		return launch
	}
	launch.pathConfig = config
	return launch
}

func launchForModule(module string, args []string, env map[string]string) pythonLaunch {
	if launch, ok := parseLauncher(module, args, env); ok {
		return launch
	}
	if _, excluded := nonApplicationModules[module]; excluded {
		return pythonLaunch{}
	}
	return pythonLaunch{target: module, targetKind: targetRunnableModule}
}

func launchForScript(script string, args []string, env map[string]string) pythonLaunch {
	command := commandName(script)
	if launch, ok := parseLauncher(command, args, env); ok {
		return launch
	}
	if command == "manage" {
		launch := parseDjango(args, env)
		if launch.target == "" {
			launch.target = script
			launch.targetKind = targetScriptPath
		}
		return launch
	}
	if script == "-" {
		return pythonLaunch{}
	}
	return pythonLaunch{target: script, targetKind: targetScriptPath}
}

func parseLauncher(command string, args []string, env map[string]string) (pythonLaunch, bool) {
	switch command {
	case "gunicorn":
		return parseGunicorn(args, env), true
	case "uvicorn":
		return parseUvicorn(args, env), true
	case "hypercorn":
		return parseHypercorn(args), true
	case "daphne":
		return parseDaphne(args), true
	case "uwsgi":
		return parseUWSGI(args), true
	case "waitress", "waitress-serve", "waitress_serve":
		return parseWaitress(args), true
	case "flask":
		return parseFlask(args, env), true
	case "fastapi":
		return parseFastAPI(args), true
	case "django", "django-admin", "django_admin":
		return parseDjango(args, env), true
	case "celery":
		return parseCelery(args), true
	default:
		return pythonLaunch{}, false
	}
}

func parseGunicorn(args []string, env map[string]string) pythonLaunch {
	var settings gunicornSettings
	fields, ok := splitShellFields(env["GUNICORN_CMD_ARGS"])
	if !ok {
		return pythonLaunch{}
	}
	if _, ok := gunicornPositionals(fields); !ok {
		return pythonLaunch{}
	}
	positionals, ok := gunicornPositionals(args)
	if !ok {
		return pythonLaunch{}
	}

	applyGunicornSettings(fields, &settings)
	applyGunicornSettings(args, &settings)

	launch := pythonLaunch{fallbackName: cleanValue(settings.name)}
	if settings.chdir != "" {
		launch.searchPaths = append(launch.searchPaths, settings.chdir)
	}
	launch.searchPaths = append(launch.searchPaths, splitList(settings.pythonPath)...)
	if target := firstApplicationReference(positionals); target != "" {
		launch.target = target
		launch.targetKind = targetModule
	}
	return launch
}

type gunicornSettings struct {
	chdir      string
	pythonPath string
	name       string
}

func applyGunicornSettings(args []string, settings *gunicornSettings) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return
		case arg == "--chdir" && i+1 < len(args):
			i++
			settings.chdir = args[i]
		case strings.HasPrefix(arg, "--chdir="):
			settings.chdir = strings.TrimPrefix(arg, "--chdir=")
		case arg == "--pythonpath" && i+1 < len(args):
			i++
			settings.pythonPath = args[i]
		case strings.HasPrefix(arg, "--pythonpath="):
			settings.pythonPath = strings.TrimPrefix(arg, "--pythonpath=")
		case (arg == "-n" || arg == "--name") && i+1 < len(args):
			i++
			settings.name = args[i]
		case strings.HasPrefix(arg, "--name="):
			settings.name = strings.TrimPrefix(arg, "--name=")
		case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--"):
			if name, ok := gunicornAttachedShortValue(arg, "-n"); ok {
				settings.name = name
			}
		}
	}
}

func parseUvicorn(args []string, env map[string]string) pythonLaunch {
	positionals, ok := uvicornPositionals(args)
	if !ok {
		return pythonLaunch{}
	}

	appDir := env["UVICORN_APP_DIR"]

options:
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--":
			break options
		case args[i] == "--app-dir" && i+1 < len(args):
			i++
			appDir = args[i]
		case strings.HasPrefix(args[i], "--app-dir="):
			appDir = strings.TrimPrefix(args[i], "--app-dir=")
		}
	}
	if appDir == "" {
		appDir = "."
	}

	launch := pythonLaunch{searchPaths: []string{appDir}}
	if target := firstApplicationReference(positionals); target != "" {
		launch.target = target
		launch.targetKind = targetModule
		return launch
	}
	if target := cleanValue(env["UVICORN_APP"]); target != "" {
		launch.target = target
		launch.targetKind = targetModule
	}
	return launch
}

func parseHypercorn(args []string) pythonLaunch {
	return parseArgparseApplication(args, hypercornOptionsWithValues, hypercornOptionsWithoutValues)
}

func parseDaphne(args []string) pythonLaunch {
	return parseArgparseApplication(args, daphneOptionsWithValues, daphneOptionsWithoutValues)
}

func parseArgparseApplication(
	args []string,
	optionsWithValues map[string]struct{},
	optionsWithoutValues map[string]struct{},
) pythonLaunch {
	positionals, ok := argparsePositionals(args, optionsWithValues, optionsWithoutValues)
	if !ok {
		return pythonLaunch{}
	}
	target := firstApplicationReference(positionals)
	if target == "" {
		return pythonLaunch{}
	}
	return pythonLaunch{target: target, targetKind: targetModule, searchPaths: []string{"."}}
}

func parseWaitress(args []string) pythonLaunch {
	target, ok := waitressApplication(args)
	if !ok || cleanValue(target) != target {
		return pythonLaunch{}
	}
	switch {
	case isStrictApplicationReference(target):
		return pythonLaunch{target: target, targetKind: targetModule}
	case strings.Contains(target, ".") && validModule(target):
		return pythonLaunch{target: target, targetKind: targetDottedReference}
	default:
		return pythonLaunch{}
	}
}

func waitressApplication(args []string) (string, bool) {
	var app string
	var positionals []string

options:
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			positionals = append(positionals, args[i+1:]...)
			break options
		case !strings.HasPrefix(arg, "-") || arg == "-":
			positionals = append(positionals, args[i:]...)
			break options
		case !strings.HasPrefix(arg, "--"):
			return "", false
		}

		name, value, attached := strings.Cut(arg, "=")
		if _, consumes := waitressOptionsWithValues[name]; consumes {
			if !attached {
				if i+1 == len(args) || !separatedOptionValue(args[i+1]) {
					return "", false
				}
				i++
				value = args[i]
			}
			if name == "--app" {
				app = value
			}
			continue
		}
		if _, known := waitressOptionsWithoutValues[name]; !known || attached {
			return "", false
		}
	}

	if app != "" {
		return app, len(positionals) == 0
	}
	if len(positionals) != 1 {
		return "", false
	}
	return positionals[0], true
}

func parseUWSGI(args []string) pythonLaunch {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case (arg == "-w" || arg == "--module") && i+1 < len(args):
			return pythonLaunch{target: args[i+1], targetKind: targetModule}
		case strings.HasPrefix(arg, "--module="):
			return pythonLaunch{target: strings.TrimPrefix(arg, "--module="), targetKind: targetModule}
		case arg == "--wsgi-file" && i+1 < len(args):
			return pythonLaunch{target: args[i+1], targetKind: targetFile}
		case strings.HasPrefix(arg, "--wsgi-file="):
			return pythonLaunch{target: strings.TrimPrefix(arg, "--wsgi-file="), targetKind: targetFile}
		}
	}
	return pythonLaunch{}
}

func parseFlask(args []string, env map[string]string) pythonLaunch {
	target := lastLongOptionValue(args, "--app", env["FLASK_APP"])
	launch := pythonLaunch{target: target, targetKind: classifyTarget(target)}
	if launch.targetKind == targetModule {
		launch.searchPaths = []string{"."}
	}
	return launch
}

func parseFastAPI(args []string) pythonLaunch {
	for i, arg := range args {
		if arg != "run" && arg != "dev" {
			if _, known := fastAPIGlobalOptionsWithoutValues[arg]; known {
				continue
			}
			return pythonLaunch{}
		}
		commandArgs, ok := parseFastAPIArguments(args[i+1:])
		if !ok {
			return pythonLaunch{}
		}
		if commandArgs.explicitEntryPoint {
			entryPoint := commandArgs.entryPoint
			if cleanValue(entryPoint) != entryPoint || commandArgs.appOption || len(commandArgs.positionals) != 0 ||
				!isStrictApplicationReference(entryPoint) {
				return pythonLaunch{}
			}
			return pythonLaunch{target: entryPoint, targetKind: targetModule, searchPaths: []string{"."}}
		}
		if len(commandArgs.positionals) == 0 {
			if commandArgs.appOption {
				return pythonLaunch{}
			}
			return pythonLaunch{fastAPIAuto: true}
		}
		if len(commandArgs.positionals) != 1 {
			return pythonLaunch{}
		}
		target := commandArgs.positionals[0]
		return pythonLaunch{target: target, targetKind: classifyTarget(target)}
	}
	return pythonLaunch{}
}

type fastAPIArguments struct {
	positionals        []string
	entryPoint         string
	explicitEntryPoint bool
	appOption          bool
}

func parseFastAPIArguments(args []string) (fastAPIArguments, bool) {
	var parsed fastAPIArguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			parsed.positionals = append(parsed.positionals, args[i+1:]...)
			return parsed, true
		}
		if strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			if _, consumes := fastAPIOptionsWithValues[name]; !consumes {
				if _, known := fastAPIOptionsWithoutValues[name]; !known || attached {
					return fastAPIArguments{}, false
				}
				continue
			}
			if !attached {
				if i+1 == len(args) {
					return fastAPIArguments{}, false
				}
				i++
				value = args[i]
			}
			switch name {
			case "--entrypoint":
				parsed.entryPoint = value
				parsed.explicitEntryPoint = true
			case "--app":
				parsed.appOption = true
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			for j := 1; j < len(arg); j++ {
				name := "-" + arg[j:j+1]
				if _, consumes := fastAPIOptionsWithValues[name]; consumes {
					value := arg[j+1:]
					if value == "" {
						if i+1 == len(args) {
							return fastAPIArguments{}, false
						}
						i++
						value = args[i]
					}
					if name == "-e" {
						parsed.entryPoint = value
						parsed.explicitEntryPoint = true
					}
					break
				}
				if _, known := fastAPIOptionsWithoutValues[name]; !known {
					return fastAPIArguments{}, false
				}
			}
			continue
		}
		parsed.positionals = append(parsed.positionals, arg)
	}
	return parsed, true
}

func parseDjango(args []string, env map[string]string) pythonLaunch {
	target := lastLongOptionValue(args, "--settings", env["DJANGO_SETTINGS_MODULE"])
	return pythonLaunch{target: target, targetKind: classifyTarget(target)}
}

func parseCelery(args []string) pythonLaunch {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case (arg == "-A" || arg == "--app") && i+1 < len(args):
			return pythonLaunch{target: args[i+1], targetKind: targetModule}
		case strings.HasPrefix(arg, "--app="):
			return pythonLaunch{target: strings.TrimPrefix(arg, "--app="), targetKind: targetModule}
		case strings.HasPrefix(arg, "-A") && len(arg) > 2:
			return pythonLaunch{target: arg[2:], targetKind: targetModule}
		}
	}
	return pythonLaunch{}
}

func classifyTarget(target string) targetKind {
	target = targetReference(target)
	if target == "" {
		return targetNone
	}
	if filepath.IsAbs(target) || strings.ContainsAny(target, `/\`) || strings.HasSuffix(strings.ToLower(target), ".py") {
		return targetFile
	}
	return targetModule
}

func targetName(target string) string {
	target = targetReference(target)
	if target == "" {
		return ""
	}
	target = strings.ReplaceAll(target, `\`, "/")
	if strings.Contains(target, "/") {
		target = strings.TrimSuffix(filepath.Base(target), filepath.Ext(target))
	} else if strings.HasSuffix(strings.ToLower(target), ".py") {
		target = strings.TrimSuffix(target, filepath.Ext(target))
	}
	parts := strings.Split(target, ".")
	for i, part := range parts {
		if strings.EqualFold(part, "settings") && i > 0 {
			return specificModuleName(parts[i-1])
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		if name := specificModuleName(parts[i]); name != "" {
			return name
		}
	}
	return ""
}

func specificModuleName(value string) string {
	value = cleanValue(value)
	if value == "" || value == "." || value == ".." || value == "-" || value == "__init__" || value == "__main__" {
		return ""
	}
	if _, generic := genericModuleNames[strings.ToLower(value)]; generic {
		return ""
	}
	return value
}

func targetReference(target string) string {
	target = strings.TrimSpace(target)
	if before, _, ok := strings.Cut(target, ":"); ok {
		target = before
	}
	return strings.TrimSpace(target)
}

func cleanValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return ""
	}
	return value
}

func commandName(path string) string {
	name := strings.ToLower(filepath.Base(path))
	return strings.TrimSuffix(name, filepath.Ext(name))
}

func isPythonInterpreter(command string) bool {
	return strings.HasPrefix(command, "python") || strings.HasPrefix(command, "pypy")
}

func isApplicationReference(value string) bool {
	module, object, ok := strings.Cut(value, ":")
	if !ok || !validModule(module) {
		return false
	}
	if before, _, found := strings.Cut(object, "("); found {
		object = before
	}
	return validModule(object)
}

func isStrictApplicationReference(value string) bool {
	module, object, ok := strings.Cut(value, ":")
	return ok && validModule(module) && validModule(object)
}

func validModule(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !validIdentifier(part) {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	for i, r := range value {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
		} else if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return value != ""
}

func firstApplicationReference(values []string) string {
	for _, value := range values {
		if isApplicationReference(value) {
			return value
		}
	}
	return ""
}

func lastLongOptionValue(args []string, option, initial string) string {
	value := initial
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == option && i+1 < len(args):
			i++
			value = args[i]
		case strings.HasPrefix(args[i], option+"="):
			value = strings.TrimPrefix(args[i], option+"=")
		}
	}
	return value
}

func gunicornPositionals(args []string) ([]string, bool) {
	var values []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(values, args[i+1:]...), true
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(arg, "=")
			if _, consumes := gunicornOptionsWithValues[name]; consumes {
				if !attached {
					if i+1 == len(args) {
						return nil, false
					}
					i++
				}
				continue
			}
			if _, known := gunicornOptionsWithoutValues[name]; !known || attached && name != "--proxy-protocol" {
				return nil, false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			consumes, known := argparseShortOption(arg, gunicornOptionsWithValues, gunicornOptionsWithoutValues)
			if !known {
				return nil, false
			}
			if consumes {
				if i+1 == len(args) {
					return nil, false
				}
				i++
			}
			continue
		}
		values = append(values, arg)
	}
	return values, true
}

func gunicornAttachedShortValue(arg, target string) (string, bool) {
	for i := 1; i < len(arg); i++ {
		name := "-" + arg[i:i+1]
		if _, known := gunicornOptionsWithoutValues[name]; known {
			continue
		}
		if _, consumes := gunicornOptionsWithValues[name]; consumes && name == target && i+1 < len(arg) {
			return strings.TrimPrefix(arg[i+1:], "="), true
		}
		return "", false
	}
	return "", false
}

func uvicornPositionals(args []string) ([]string, bool) {
	var values []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(values, args[i+1:]...), true
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(arg, "=")
			if _, consumes := uvicornOptionsWithValues[name]; consumes {
				if !attached {
					if i+1 == len(args) {
						return nil, false
					}
					i++
				}
				continue
			}
			if _, known := uvicornOptionsWithoutValues[name]; !known || attached {
				return nil, false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			return nil, false
		}
		values = append(values, arg)
	}
	return values, true
}

func argparsePositionals(
	args []string,
	optionsWithValues map[string]struct{},
	optionsWithoutValues map[string]struct{},
) ([]string, bool) {
	var values []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(values, args[i+1:]...), true
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(arg, "=")
			if _, consumes := optionsWithValues[name]; consumes {
				if !attached {
					if i+1 == len(args) || !separatedOptionValue(args[i+1]) {
						return nil, false
					}
					i++
				}
				continue
			}
			if _, known := optionsWithoutValues[name]; !known || attached {
				return nil, false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			consumes, known := argparseShortOption(arg, optionsWithValues, optionsWithoutValues)
			if !known {
				return nil, false
			}
			if consumes {
				if i+1 == len(args) || !separatedOptionValue(args[i+1]) {
					return nil, false
				}
				i++
			}
			continue
		}
		values = append(values, arg)
	}
	return values, true
}

func separatedOptionValue(value string) bool {
	if value == "-" || !strings.HasPrefix(value, "-") {
		return true
	}

	digits := 0
	dot := false
	for i := 1; i < len(value); i++ {
		switch {
		case value[i] >= '0' && value[i] <= '9':
			digits++
		case value[i] == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits > 0 && value[len(value)-1] != '.'
}

func argparseShortOption(
	arg string,
	optionsWithValues map[string]struct{},
	optionsWithoutValues map[string]struct{},
) (bool, bool) {
	for i := 1; i < len(arg); i++ {
		name := "-" + arg[i:i+1]
		if _, known := optionsWithoutValues[name]; known {
			continue
		}
		if _, consumes := optionsWithValues[name]; consumes {
			return i == len(arg)-1, true
		}
		return false, false
	}
	return false, true
}

func splitShellFields(value string) ([]string, bool) {
	var fields []string
	var field strings.Builder
	var quote rune
	escaped := false
	started := false
	flush := func() {
		if started {
			fields = append(fields, field.String())
			field.Reset()
			started = false
		}
	}

	for _, r := range value {
		if escaped {
			field.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				field.WriteRune(r)
			}
			started = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		field.WriteRune(r)
		started = true
	}
	if quote != 0 || escaped {
		return nil, false
	}
	flush()
	return fields, true
}

func splitList(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

var gunicornOptionsWithValues = optionSet(
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
)

var gunicornOptionsWithoutValues = optionSet(
	"--reload", "--spew", "--check-config", "--print-config", "--preload", "--no-sendfile", "--reuse-port",
	"-D", "--daemon", "--initgroups", "--disable-redirect-access-to-syslog", "--capture-output",
	"--log-syslog", "-R", "--enable-stdio-inheritance", "--enable-backlog-metric", "--suppress-ragged-eofs",
	"--do-handshake-on-connect", "--permit-obsolete-folding", "--strip-header-spaces",
	"--permit-unconventional-http-method", "--permit-unconventional-http-version", "--casefold-http-method",
	"--no-control-socket", "-h", "--help", "-v", "--version", "--proxy-protocol",
)

var uvicornOptionsWithValues = optionSet(
	"--host", "--port", "--uds", "--fd", "--reload-dir", "--reload-delay", "--reload-include", "--reload-exclude",
	"--workers", "--env-file", "--timeout-worker-healthcheck", "--log-config", "--log-level", "--loop", "--http",
	"--ws", "--ws-max-size", "--ws-max-queue", "--ws-ping-interval", "--ws-ping-timeout", "--ws-per-message-deflate",
	"--lifespan", "--h11-max-incomplete-event-size", "--interface", "--root-path", "--forwarded-allow-ips", "--header",
	"--ssl-keyfile", "--ssl-keyfile-password", "--ssl-certfile", "--ssl-version", "--ssl-cert-reqs", "--ssl-ca-certs",
	"--ssl-ciphers", "--app-dir", "--limit-concurrency", "--backlog", "--limit-max-requests",
	"--limit-max-requests-jitter", "--timeout-keep-alive", "--timeout-graceful-shutdown",
)

var uvicornOptionsWithoutValues = optionSet(
	"--reload", "--access-log", "--no-access-log", "--use-colors", "--no-use-colors", "--proxy-headers",
	"--no-proxy-headers", "--server-header", "--no-server-header", "--date-header", "--no-date-header",
	"--version", "--reset-contextvars", "--factory", "--help",
)

var hypercornOptionsWithValues = optionSet(
	"--access-log", "--access-logfile", "--access-logformat", "--backlog", "-b", "--bind", "--ca-certs",
	"--certfile", "--cert-reqs", "--ciphers", "-c", "--config", "--error-log", "--error-logfile", "--log-file",
	"--graceful-timeout", "--read-timeout", "--max-requests", "--max-requests-jitter", "-g", "--group", "-k",
	"--worker-class", "--keep-alive", "--keyfile", "--keyfile-password", "--insecure-bind", "--log-config",
	"--log-level", "-p", "--pid", "--quic-bind", "--root-path", "--server-name", "--statsd-host",
	"--statsd-prefix", "-m", "--umask", "-u", "--user", "--verify-mode", "--websocket-ping-interval", "-w",
	"--workers",
)

var hypercornOptionsWithoutValues = optionSet(
	"-D", "--daemon", "--debug", "--reload", "-h", "--help",
)

var daphneOptionsWithValues = optionSet(
	"-p", "--port", "-b", "--bind", "--websocket_timeout", "--websocket_connect_timeout", "-u",
	"--unix-socket", "--fd", "-e", "--endpoint", "-v", "--verbosity", "-t", "--http-timeout",
	"--access-log", "--log-fmt", "--ping-interval", "--ping-timeout", "--websocket-max-message-size",
	"--websocket-max-frame-size", "--application-close-timeout", "--root-path", "--proxy-headers-host",
	"--proxy-headers-port", "-s", "--server-name",
)

var daphneOptionsWithoutValues = optionSet(
	"--proxy-headers", "--no-server-name", "-h", "--help",
)

var waitressOptionsWithValues = optionSet(
	"--host", "--port", "--listen", "--threads", "--trusted-proxy", "--trusted-proxy-count",
	"--trusted-proxy-headers", "--url-scheme", "--url-prefix", "--backlog", "--recv-bytes", "--send-bytes",
	"--outbuf-overflow", "--outbuf-high-watermark", "--inbuf-overflow", "--connection-limit",
	"--cleanup-interval", "--channel-timeout", "--max-request-header-size", "--max-request-body-size",
	"--ident", "--asyncore-loop-timeout", "--unix-socket", "--unix-socket-perms", "--sockets",
	"--channel-request-lookahead", "--server-name", "--app",
)

var waitressOptionsWithoutValues = optionSet(
	"--help", "--call", "--ipv4", "--no-ipv4", "--ipv6", "--no-ipv6", "--log-untrusted-proxy-headers",
	"--no-log-untrusted-proxy-headers", "--clear-untrusted-proxy-headers", "--no-clear-untrusted-proxy-headers",
	"--log-socket-errors", "--no-log-socket-errors", "--expose-tracebacks", "--no-expose-tracebacks",
	"--asyncore-use-poll", "--no-asyncore-use-poll",
)

var fastAPIOptionsWithValues = optionSet(
	"--host", "--port", "--uds", "--fd", "--app", "--entrypoint", "-e", "--root-path",
	"--forwarded-allow-ips", "--workers", "--reload-delay", "--reload-dir", "--reload-include", "--reload-exclude",
)

var fastAPIOptionsWithoutValues = optionSet(
	"--reload", "--no-reload", "--proxy-headers", "--no-proxy-headers", "--verbose", "-v", "--help", "-h",
)

var fastAPIGlobalOptionsWithoutValues = optionSet(
	"--verbose", "--no-verbose",
)

func optionSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
