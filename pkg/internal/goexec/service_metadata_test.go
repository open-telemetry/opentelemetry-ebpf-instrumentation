// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoModuleNamespace(t *testing.T) {
	for path, want := range map[string]string{
		"github.com/acme/checkout/v2":       "acme",
		"gitlab.com/acme/platform/checkout": "acme",
		"bitbucket.org/acme/web":            "acme",
		"go.opentelemetry.io/obi":           "opentelemetry",
		"go.acme.co.uk/payments":            "acme",
		"go.uber.org/zap":                   "uber",
		"team.github.io/checkout":           "team",
		"codeberg.org/knut/foobar":          "knut",
		"gitea.com/acme/checkout":           "acme",
		"gitee.com/acme/checkout":           "acme",
		"git.sr.ht/~sbinet/gg":              "sbinet",
		"git.sr.ht/sbinet/gg":               "",
		"git.sr.ht/~sbinet":                 "",
		"git.sr.ht/~/gg":                    "",
		"github.com/acme":                   "",
		"gopkg.in/yaml.v3":                  "",
		"127.0.0.1/checkout":                "",
		"co.uk/service":                     "",
		"checkout":                          "",
		"":                                  "",
		"command-line-arguments":            "",
	} {
		t.Run(path, func(t *testing.T) { assert.Equal(t, want, goModuleNamespace(path)) })
	}
}
