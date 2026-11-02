// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/transform"
)

func TestCloudAPIsWithoutCloudMetadata(t *testing.T) {
	refreshers := transform.CloudMetadataRefreshers(t.Context(), &metadata.NodeMeta{}, nil, transform.CloudMetadataConfig{})
	require.Empty(t, refreshers)
	input, output := msg.NewQueue[exec.ProcessEvent](), msg.NewQueue[exec.ProcessEvent]()
	provider := transform.CloudProcessEventDecoratorProvider(&global.ContextInfo{}, input, output)
	run, err := provider(t.Context())
	require.NoError(t, err)
	require.NotNil(t, run)
}
