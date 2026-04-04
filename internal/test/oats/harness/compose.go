// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness // import "go.opentelemetry.io/obi/internal/test/oats/harness"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/grafana/oats/model"
	"github.com/grafana/oats/testhelpers/remote"
	oatsyaml "github.com/grafana/oats/yaml"
	"github.com/onsi/ginkgo/v2"
)

type compose struct {
	path   string
	logger io.WriteCloser
	env    []string
}

func startEndpoint(c *model.TestCase, settings model.Settings, logFile string) (*remote.Endpoint, error) {
	composePath := oatsyaml.CreateDockerComposeFile(oatsyaml.NewRunner(c, settings))
	compose, err := newCompose(composePath, logFile)
	if err != nil {
		return nil, err
	}

	ports := remote.PortsConfig{
		PrometheusHTTPPort: c.PortConfig.PrometheusHTTPPort,
		TempoHTTPPort:      c.PortConfig.TempoHTTPPort,
		LokiHttpPort:       c.PortConfig.LokiHTTPPort,
		PyroscopeHttpPort:  c.PortConfig.PyroscopeHttpPort,
	}

	return remote.NewEndpoint(
		settings.Host,
		ports,
		func(context.Context) error {
			return compose.up()
		},
		func(context.Context) error {
			return compose.close()
		},
		func(consume func(io.ReadCloser, *sync.WaitGroup)) error {
			return compose.logsToConsumer(consume)
		},
	), nil
}

func newCompose(composeFile, logFile string) (*compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, err
	}

	abs, err := filepath.Abs(logFile)
	if err == nil {
		ginkgo.GinkgoWriter.Printf("Logging to %s\n", abs)
	}

	return &compose{
		path:   composeFile,
		logger: logs,
		env:    os.Environ(),
	}, nil
}

func (c *compose) up() error {
	return c.command("up", "--build", "--detach", "--force-recreate")
}

func (c *compose) logsToConsumer(consume func(io.ReadCloser, *sync.WaitGroup)) error {
	cmd := exec.Command("docker", "compose", "--ansi", "never", "-f", c.path, "logs")
	cmd.Env = c.env

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create compose logs pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	var wg sync.WaitGroup
	wg.Add(1)
	go consume(stdout, &wg)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start docker compose logs: %w", err)
	}

	waitErr := cmd.Wait()
	wg.Wait()
	if waitErr != nil {
		return fmt.Errorf("failed to run docker compose logs: %w", waitErr)
	}

	return nil
}

func (c *compose) close() error {
	var errs []string

	if err := c.command("logs"); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.command("stop"); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.command("rm", "-f"); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.logger.Close(); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.New(strings.Join(errs, " / "))
}

func (c *compose) command(args ...string) error {
	cmdArgs := []string{"compose", "--ansi", "never", "-f", c.path}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.env
	cmd.Stdout = c.logger
	cmd.Stderr = c.logger

	if _, err := fmt.Fprintf(c.logger, "Running: docker %s\n", strings.Join(cmdArgs, " ")); err != nil {
		return fmt.Errorf("failed to write compose command header: %w", err)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run docker compose %s: %w", strings.Join(args, " "), err)
	}

	return nil
}
