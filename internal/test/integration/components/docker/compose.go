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
	"strings"
	"time"

	"go.opentelemetry.io/obi/internal/test/tools"
)

// stopTimeout bounds how long `docker compose stop` waits between SIGTERM and
// SIGKILL for each container. Keeps shutdown predictable when a container is
// hung.
const stopTimeout = "5"

// waitTimeout bounds how long Close() will wait for the obi container to
// exit. A stuck container would otherwise burn the shard's job timeout.
const waitTimeout = 30 * time.Second

type Compose struct {
	Path   string
	Logger io.WriteCloser
	Env    []string
}

func defaultEnv() []string {
	env := os.Environ()
	env = append(env, "OTEL_EBPF_EXECUTABLE_PATH=testserver")
	env = append(env, "JAVA_EXECUTABLE_PATH=greeting")
	return env
}

func ComposeSuite(composeFile, logFile string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, err
	}

	// Construct the full path to the Docker Compose file
	projectRoot := tools.ProjectDir()
	composePath := filepath.Join(projectRoot, "internal", "test", "integration", composeFile)

	return &Compose{
		Path:   composePath,
		Logger: logs,
		Env:    defaultEnv(),
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
	return c.command("up", "--build", "--detach", "--quiet-pull")
}

func (c *Compose) Logs() error {
	return c.command("logs")
}

func (c *Compose) Stop() error {
	return c.command("stop", "--timeout", stopTimeout)
}

func (c *Compose) Remove() error {
	return c.command("rm", "-f", "-v")
}

func (c *Compose) command(args ...string) error {
	return c.commandContext(context.Background(), args...)
}

func (c *Compose) commandContext(ctx context.Context, args ...string) error {
	cmdArgs := []string{"compose", "--ansi", "never", "-f", c.Path}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Env = c.Env
	if c.Logger != nil {
		cmd.Stdout = c.Logger
		cmd.Stderr = c.Logger
	}
	return cmd.Run()
}

func (c *Compose) ExecOutput(service string, args ...string) (string, error) {
	cmdArgs := []string{"compose", "--ansi", "never", "-f", c.Path, "exec", "-T", service}
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

	waitCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	if err := c.commandContext(waitCtx, "wait", "obi"); err != nil {
		slog.Warn("waiting for obi to stop. Will force remove", "error", err)
	}
	cancel()

	if err := c.Remove(); err != nil {
		errs = append(errs, fmt.Errorf("removing container: %w", err))
	}

	if err := c.Logger.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing logger: %w", err))
	}

	return errors.Join(errs...)
}
