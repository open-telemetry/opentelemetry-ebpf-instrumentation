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
	"slices"
	"strings"
	"sync"

	"github.com/grafana/oats/model"
	"github.com/grafana/oats/testhelpers/remote"
	oatsyaml "github.com/grafana/oats/yaml"
	"github.com/onsi/ginkgo/v2"
	"go.yaml.in/yaml/v3"
)

const (
	prebuiltOBIImage = "hatest-obi"
	obiDockerfile    = "internal/test/integration/components/obi/Dockerfile"
)

type compose struct {
	path   string
	files  []string
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
		files:  []string{composeFile},
		logger: logs,
		env:    os.Environ(),
	}, nil
}

func (c *compose) up() error {
	if !prebuiltOBIAvailable() {
		return c.command("up", "--build", "--detach", "--force-recreate")
	}

	obiServices, toBuild, err := c.splitServices()
	if err != nil {
		ginkgo.GinkgoWriter.Printf("prebuilt %s not used, building all services: %v\n", prebuiltOBIImage, err)
		return c.command("up", "--build", "--detach", "--force-recreate")
	}
	if len(obiServices) == 0 {
		ginkgo.GinkgoWriter.Printf("prebuilt %s not used, no service builds the OBI Dockerfile\n", prebuiltOBIImage)
		return c.command("up", "--build", "--detach", "--force-recreate")
	}

	if err := c.usePrebuiltOBI(obiServices); err != nil {
		return err
	}
	ginkgo.GinkgoWriter.Printf("using prebuilt %s for %s\n", prebuiltOBIImage, strings.Join(obiServices, ", "))
	if len(toBuild) > 0 {
		if err := c.command(append([]string{"build"}, toBuild...)...); err != nil {
			return err
		}
	}
	return c.command("up", "--detach", "--force-recreate")
}

func prebuiltOBIAvailable() bool {
	prebuilt := strings.Split(os.Getenv("PREBUILT_IMAGES"), ",")
	for i := range prebuilt {
		prebuilt[i] = strings.TrimSpace(prebuilt[i])
	}
	if !slices.Contains(prebuilt, prebuiltOBIImage) {
		return false
	}
	return exec.Command("docker", "image", "inspect", prebuiltOBIImage).Run() == nil
}

func (c *compose) splitServices() (obiServices, toBuild []string, err error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, nil, err
	}

	var doc struct {
		Services map[string]struct {
			Build *struct {
				Context    string         `yaml:"context"`
				Dockerfile string         `yaml:"dockerfile"`
				Args       map[string]any `yaml:"args"`
				Target     string         `yaml:"target"`
			} `yaml:"build"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}

	for name, svc := range doc.Services {
		if svc.Build == nil {
			continue
		}
		dockerfile := svc.Build.Dockerfile
		if filepath.IsAbs(dockerfile) {
			if rel, err := filepath.Rel(svc.Build.Context, dockerfile); err == nil {
				dockerfile = rel
			}
		}
		if filepath.ToSlash(filepath.Clean(dockerfile)) == obiDockerfile &&
			len(svc.Build.Args) == 0 && svc.Build.Target == "" {
			obiServices = append(obiServices, name)
		} else {
			toBuild = append(toBuild, name)
		}
	}
	slices.Sort(obiServices)
	slices.Sort(toBuild)

	return obiServices, toBuild, nil
}

func (c *compose) usePrebuiltOBI(services []string) error {
	override := map[string]map[string]map[string]string{"services": {}}
	for _, name := range services {
		override["services"][name] = map[string]string{"image": prebuiltOBIImage}
	}
	data, err := yaml.Marshal(override)
	if err != nil {
		return err
	}

	path := filepath.Join(filepath.Dir(c.path), "docker-compose-prebuilt-obi.yml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	c.files = append(c.files, path)
	return nil
}

func (c *compose) logsToConsumer(consume func(io.ReadCloser, *sync.WaitGroup)) error {
	cmd := exec.Command("docker", append(c.baseArgs(), "logs")...)
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

func (c *compose) baseArgs() []string {
	args := []string{"compose", "--ansi", "never"}
	for _, f := range c.files {
		args = append(args, "-f", f)
	}
	return args
}

func (c *compose) command(args ...string) error {
	cmdArgs := append(c.baseArgs(), args...)
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
