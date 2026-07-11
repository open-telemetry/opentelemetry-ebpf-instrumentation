// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {
	assert.Equal(t, "thens/thename", (&Attrs{UID: UID{Namespace: "thens", Name: "thename"}}).String())
	assert.Equal(t, "thename", (&Attrs{UID: UID{Name: "thename"}}).String())
}

func TestFormattingExcludesEnvVars(t *testing.T) {
	a := Attrs{
		UID:     UID{Namespace: "ns", Name: "svc"},
		EnvVars: map[string]string{"SOME_VAR": "some-value"},
	}
	nested := struct{ Service Attrs }{Service: a}

	for name, out := range map[string]string{
		"value":   fmt.Sprintf("%+v", a),
		"pointer": fmt.Sprintf("%+v", &a),
		"nested":  fmt.Sprintf("%+v", nested),
	} {
		assert.NotContains(t, out, "some-value", name)
		assert.NotContains(t, out, "SOME_VAR", name)
	}
}

// the JSON handler does not use String(): without LogValue it marshals every exported field
func TestSlogExcludesEnvVars(t *testing.T) {
	a := Attrs{
		UID:     UID{Namespace: "ns", Name: "svc"},
		EnvVars: map[string]string{"SOME_VAR": "some-value"},
	}

	for name, newHandler := range map[string]func(io.Writer) slog.Handler{
		"text": func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
		"json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		var buf bytes.Buffer
		log := slog.New(newHandler(&buf))

		log.Info("value", "service", a)
		log.Info("pointer", "service", &a)
		log.With("service", &a).Info("with")

		out := buf.String()
		assert.NotContains(t, out, "some-value", name)
		assert.NotContains(t, out, "SOME_VAR", name)
		assert.Contains(t, out, "ns/svc", name)
	}
}
