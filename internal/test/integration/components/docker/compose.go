// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package docker provides some helpers to manage docker-compose clusters from the test suites
package docker // import "go.opentelemetry.io/obi/internal/test/integration/components/docker"

import (
	"context"
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

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/test/tools"
)

// stopTimeout bounds how long `docker compose stop` waits between SIGTERM and
// SIGKILL for each container. Keeps shutdown predictable when a container is
// hung.
const stopTimeout = "15"

// waitTimeout bounds how long Close() will wait for the obi container to
// exit. A stuck container would otherwise burn the shard's job timeout.
const waitTimeout = 30 * time.Second

type Compose struct {
	Path          string
	OverridePaths []string
	Logger        io.WriteCloser
	Env           []string
	skipWait      bool
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
			if err := c.command(append([]string{"build"}, services...)...); err != nil {
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
	prebuiltEnv := os.Getenv("PREBUILT_IMAGES")
	if prebuiltEnv == "" {
		return nil, false
	}
	prebuilt := strings.Split(prebuiltEnv, ",")
	for i := range prebuilt {
		prebuilt[i] = strings.TrimSpace(prebuilt[i])
	}

	type composeDocument struct {
		Services map[string]struct {
			Image string    `yaml:"image"`
			Build yaml.Node `yaml:"build"`
		} `yaml:"services"`
	}

	services := map[string]struct {
		Image string
		Build yaml.Node
	}{}
	for _, composePath := range c.composePaths() {
		data, err := os.ReadFile(composePath)
		if err != nil {
			return nil, false
		}

		var doc composeDocument
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
			services[name] = service
		}
	}

	var servicesToBuild []string
	for name, svc := range services {
		if svc.Build.IsZero() {
			continue
		}
		if svc.Image != "" && slices.Contains(prebuilt, svc.Image) {
			continue
		}
		servicesToBuild = append(servicesToBuild, name)
	}
	slices.Sort(servicesToBuild)

	return servicesToBuild, true
}

func (c *Compose) Run(service string) error {
	c.skipWait = true
	args := []string{"up"}
	if os.Getenv("SKIP_DOCKER_BUILD") == "" {
		if services, ok := c.servicesToBuild(); ok {
			if len(services) > 0 {
				if err := c.command(append([]string{"build"}, services...)...); err != nil {
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

func (c *Compose) Stop() error {
	return c.command("stop", "--timeout", stopTimeout)
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

	if !c.skipWait {
		waitCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		if err := c.commandContext(waitCtx, "wait", "obi"); err != nil {
			slog.Warn("waiting for obi to stop. Will force remove", "error", err)
		}
		cancel()
	}

	if err := c.Remove(); err != nil {
		errs = append(errs, fmt.Errorf("removing container: %w", err))
	}

	if err := c.Logger.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing logger: %w", err))
	}

	return errors.Join(errs...)
}
