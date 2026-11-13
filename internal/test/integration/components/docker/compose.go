// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package docker provides some helpers to manage docker-compose clusters from the test suites
package docker // import "go.opentelemetry.io/obi/internal/test/integration/components/docker"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/test/tools"
)

// stopTimeout bounds how long `docker compose stop` waits between SIGTERM and
// SIGKILL for each container. Keeps shutdown predictable when a container is
// hung.
const stopTimeout = "15"

const configMigrationOverride = "docker-compose-config-migration.yml"

// hex digits of the build definition digest logged with each build; enough to tell definitions apart
const buildDigestLength = 12

type composeService struct {
	Image    string    `yaml:"image"`
	Build    yaml.Node `yaml:"build"`
	Profiles []string  `yaml:"profiles"`
}

type ConfigMigration struct {
	Source string
	Output string
	Image  string
}

type Compose struct {
	Path          string
	OverridePaths []string
	Logger        io.WriteCloser
	Env           []string
}

func defaultEnv() []string {
	env := os.Environ()
	env = append(env, "OTEL_EBPF_EXECUTABLE_PATH=testserver")
	env = append(env, "JAVA_EXECUTABLE_PATH=greeting")
	return env
}

func ComposeSuite(composeFile, logFile string) (*Compose, error) {
	return ComposeSuiteWithOverrides(composeFile, logFile)
}

func ComposeSuiteWithConfigMigration(
	composeFile, logFile string,
	migration ConfigMigration,
) (*Compose, error) {
	compose, err := ComposeSuiteWithOverrides(composeFile, logFile, configMigrationOverride)
	if err != nil {
		return nil, err
	}

	compose.Env = append(
		compose.Env,
		"OBI_CONFIG_MIGRATION_SOURCE="+migration.Source,
		"OBI_CONFIG_MIGRATION_OUTPUT="+migration.Output,
		"OBI_CONFIG_MIGRATION_IMAGE="+migration.Image,
	)
	return compose, nil
}

func ComposeSuiteWithOverrides(composeFile, logFile string, overrideFiles ...string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, err
	}

	// Construct the full path to the Docker Compose file
	projectRoot := tools.ProjectDir()
	integrationPath := filepath.Join(projectRoot, "internal", "test", "integration")
	composePath := filepath.Join(integrationPath, composeFile)
	overridePaths := make([]string, 0, len(overrideFiles))
	for _, overrideFile := range overrideFiles {
		overridePaths = append(overridePaths, filepath.Join(integrationPath, overrideFile))
	}

	return &Compose{
		Path:          composePath,
		OverridePaths: overridePaths,
		Logger:        logs,
		Env:           defaultEnv(),
	}, nil
}

func (c *Compose) Up() error {
	// When SKIP_DOCKER_BUILD is set, Docker images have been pre-built on the host
	// and loaded into the VM's Docker daemon. Skip --build to avoid rebuilding them
	// inside the VM (which is extremely slow under TCG/software CPU emulation).
	// Without --build, compose will still auto-build any missing images.
	if os.Getenv("SKIP_DOCKER_BUILD") != "" {
		return c.command("up", "--detach", "--quiet-pull")
	}

	if services, ok := c.servicesToBuild(); ok {
		if len(services) > 0 {
			if err := c.build(services); err != nil {
				return err
			}
		}
		return c.command("up", "--detach", "--quiet-pull")
	}

	return c.command("up", "--build", "--detach", "--quiet-pull")
}

// servicesToBuild lists the services to rebuild when PREBUILT_IMAGES names
// image tags that were docker-loaded before the run: everything with a build
// section except the prebuilt ones. Image tags are not unique per Dockerfile
// across compose files, so all other services must keep rebuilding per suite.
// Returns ok=false (build everything) when the mechanism is off or the file
// can't be parsed
func (c *Compose) servicesToBuild() ([]string, bool) {
	prebuilt := prebuiltImages()
	if len(prebuilt) == 0 {
		return nil, false
	}

	services, ok := c.services()
	if !ok {
		return nil, false
	}

	var servicesToBuild []string
	for name, svc := range services {
		if svc.Build.IsZero() || !c.profileActive(svc.Profiles) {
			continue
		}
		if image := c.interpolate(svc.Image); image != "" && slices.Contains(prebuilt, image) {
			continue
		}
		servicesToBuild = append(servicesToBuild, name)
	}
	slices.Sort(servicesToBuild)

	return servicesToBuild, true
}

// build logs its duration and images in the test output, where the test weights script finds
// builds of images that several suites share
func (c *Compose) build(services []string) error {
	started := time.Now()
	if err := c.command(append([]string{"build"}, services...)...); err != nil {
		return err
	}

	slog.Info("built compose services",
		"seconds", int(time.Since(started).Round(time.Second).Seconds()),
		"images", strings.Join(c.builds(services), ","))
	return nil
}

// builds names what each service builds: its image plus a digest of the resolved build definition, because
// the same tag is built from different Dockerfiles or arguments across compose files
func (c *Compose) builds(services []string) []string {
	definitions, _ := c.services()
	builds := make([]string, 0, len(services))
	for _, name := range services {
		service := definitions[name]
		image := c.interpolate(service.Image)
		if image == "" {
			image = filepath.Base(c.Path) + "/" + name
		}

		definition, _ := yaml.Marshal(&service.Build)
		digest := sha256.New()
		fmt.Fprintf(digest, "%s\n%s", filepath.Dir(c.Path), c.interpolate(string(definition)))
		for _, arg := range environmentBuildArgs(service.Build) {
			value, _ := c.lookupEnv(arg)
			fmt.Fprintf(digest, "\n%s=%s", arg, value)
		}
		builds = append(builds, image+"@"+hex.EncodeToString(digest.Sum(nil))[:buildDigestLength])
	}
	return builds
}

// environmentBuildArgs lists the build args given only by name, whose values compose reads from the environment
func environmentBuildArgs(build yaml.Node) []string {
	if build.Kind != yaml.MappingNode {
		return nil
	}
	var names []string
	for i := 0; i+1 < len(build.Content); i += 2 {
		if build.Content[i].Value != "args" {
			continue
		}
		args := build.Content[i+1]
		switch args.Kind {
		case yaml.SequenceNode:
			for _, arg := range args.Content {
				if !strings.Contains(arg.Value, "=") {
					names = append(names, arg.Value)
				}
			}
		case yaml.MappingNode:
			for j := 0; j+1 < len(args.Content); j += 2 {
				if args.Content[j+1].Tag == "!!null" {
					names = append(names, args.Content[j].Value)
				}
			}
		}
	}
	return names
}

// services merges the service definitions of the compose file and its overrides
func (c *Compose) services() (map[string]composeService, bool) {
	services := map[string]composeService{}
	for _, composePath := range c.composePaths() {
		data, err := os.ReadFile(composePath)
		if err != nil {
			return nil, false
		}

		var doc struct {
			Services map[string]composeService `yaml:"services"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, false
		}
		for name, overlay := range doc.Services {
			service := services[name]
			if overlay.Image != "" {
				service.Image = overlay.Image
			}
			if !overlay.Build.IsZero() {
				service.Build = overlay.Build
			}
			if len(overlay.Profiles) > 0 {
				service.Profiles = overlay.Profiles
			}
			services[name] = service
		}
	}
	return services, true
}

// obiServices lists the services running OBI, such as obi or client-obi
func (c *Compose) obiServices() ([]string, bool) {
	services, ok := c.services()
	if !ok {
		return nil, false
	}

	var obiServices []string
	for name := range services {
		if slices.Contains(strings.Split(name, "-"), "obi") {
			obiServices = append(obiServices, name)
		}
	}
	slices.Sort(obiServices)

	return obiServices, true
}

// profileActive mirrors compose: services without profiles always run, others need one in COMPOSE_PROFILES
func (c *Compose) profileActive(profiles []string) bool {
	if len(profiles) == 0 {
		return true
	}

	value, _ := c.lookupEnv("COMPOSE_PROFILES")
	active := strings.Split(value, ",")
	return slices.ContainsFunc(profiles, func(p string) bool {
		return slices.Contains(active, p)
	})
}

// interpolate resolves the ${VAR}, ${VAR:-default} and ${VAR-default} forms the same way compose does
func (c *Compose) interpolate(s string) string {
	return os.Expand(s, func(expr string) string {
		nameEnd := strings.IndexFunc(expr, func(r rune) bool {
			return r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		if nameEnd < 0 {
			value, _ := c.lookupEnv(expr)
			return value
		}

		name, modifier := expr[:nameEnd], expr[nameEnd:]
		value, set := c.lookupEnv(name)
		if fallback, ok := strings.CutPrefix(modifier, ":-"); ok && value == "" {
			return fallback
		}
		if fallback, ok := strings.CutPrefix(modifier, "-"); ok && !set {
			return fallback
		}
		return value
	})
}

// lookupEnv reads the compose environment, where later entries override earlier ones
func (c *Compose) lookupEnv(name string) (string, bool) {
	for _, entry := range slices.Backward(c.Env) {
		if value, ok := strings.CutPrefix(entry, name+"="); ok {
			return value, true
		}
	}
	return "", false
}

func (c *Compose) Run(service string) error {
	args := []string{"up"}
	if os.Getenv("SKIP_DOCKER_BUILD") == "" {
		if services, ok := c.servicesToBuild(); ok {
			if len(services) > 0 {
				if err := c.build(services); err != nil {
					return err
				}
			}
		} else {
			args = append(args, "--build")
		}
	}
	args = append(args, "--quiet-pull", "--abort-on-container-exit", "--exit-code-from", service)
	return c.command(args...)
}

func (c *Compose) Logs() error {
	return c.command("logs")
}

func (c *Compose) LogsOutput(services ...string) (string, error) {
	cmdArgs := c.composeArgs("logs")
	cmdArgs = append(cmdArgs, services...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.CombinedOutput()

	if c.Logger != nil && len(output) > 0 {
		if _, writeErr := c.Logger.Write(output); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}

	return strings.TrimSpace(string(output)), err
}

// LogsTail returns the last n lines without echoing them into the suite log: callers that
// poll would otherwise append the whole container log on every attempt.
func (c *Compose) LogsTail(n int, services ...string) (string, error) {
	cmdArgs := c.composeArgs("logs", "--no-log-prefix", "--tail", strconv.Itoa(n))
	cmdArgs = append(cmdArgs, services...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.Output()

	return strings.TrimSpace(string(output)), err
}

// ServiceRunning reports whether Compose currently lists a service as running.
func (c *Compose) ServiceRunning(service string) (bool, error) {
	cmdArgs := []string{"compose", "--ansi", "never", "-f", c.Path, "ps", "--status", "running", "--services", service}
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(output)) == service, nil
}

// Stop lets OBI exit cleanly, so it writes coverage and exports to a collector that is still up, then kills
// the rest: fixtures that ignore SIGTERM would otherwise hold every teardown for the whole stop timeout
func (c *Compose) Stop() error {
	obiServices, ok := c.obiServices()
	if !ok {
		return c.command("stop", "--timeout", stopTimeout)
	}

	if len(obiServices) > 0 {
		if err := c.command(append([]string{"stop", "--timeout", stopTimeout}, obiServices...)...); err != nil {
			return err
		}
	}
	return c.command("kill")
}

func (c *Compose) Remove() error {
	cmdArgs := c.composeArgs("rm", "-f", "-s", "-v")
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.CombinedOutput()
	if c.Logger != nil && len(output) > 0 {
		if _, writeErr := c.Logger.Write(output); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}

	if err != nil && strings.Contains(string(output), "already in progress") {
		return nil
	}

	return err
}

func (c *Compose) command(args ...string) error {
	return c.commandContext(context.Background(), args...)
}

func (c *Compose) commandContext(ctx context.Context, args ...string) error {
	cmdArgs := c.composeArgs(args...)
	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Env = c.Env
	if c.Logger != nil {
		cmd.Stdout = c.Logger
		cmd.Stderr = c.Logger
	}
	return cmd.Run()
}

// Exec runs `docker exec <container> <args...>`. Use when there's no Compose handle.
func Exec(ctx context.Context, container string, args ...string) (string, error) {
	cmdArgs := append([]string{"exec", container}, args...)
	out, err := exec.CommandContext(ctx, "docker", cmdArgs...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)),
			fmt.Errorf("docker exec %s %v: %w; output: %s", container, args, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *Compose) ExecOutput(service string, args ...string) (string, error) {
	cmdArgs := c.composeArgs("exec", "-T", service)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.CombinedOutput()

	if c.Logger != nil && len(output) > 0 {
		if _, writeErr := c.Logger.Write(output); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}
	return strings.TrimSpace(string(output)), err
}

func (c *Compose) composePaths() []string {
	return append([]string{c.Path}, c.OverridePaths...)
}

func (c *Compose) composeArgs(args ...string) []string {
	cmdArgs := []string{"compose", "--ansi", "never"}
	for _, composePath := range c.composePaths() {
		cmdArgs = append(cmdArgs, "-f", composePath)
	}
	return append(cmdArgs, args...)
}

func (c *Compose) Close() error {
	var errs []error

	// Logs is read-only; run it in parallel with Stop so neither blocks the other.
	logsErr := make(chan error, 1)
	go func() {
		logsErr <- c.Logs()
	}()

	if err := c.Stop(); err != nil {
		// we just warn, as the container will be force-removed later
		slog.Warn("stopping docker compose. Will force remove", "error", err)
	}

	if err := <-logsErr; err != nil {
		errs = append(errs, fmt.Errorf("flushing logs: %w", err))
	}

	if err := c.Remove(); err != nil {
		errs = append(errs, fmt.Errorf("removing container: %w", err))
	}

	if err := c.Logger.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing logger: %w", err))
	}

	return errors.Join(errs...)
}
