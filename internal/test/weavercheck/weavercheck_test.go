// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtendsNamespaceAdviceIsActionable exercises weaver's serialized
// finding ID so information-level namespace extensions cannot silently
// bypass semantic convention validation.
func TestExtendsNamespaceAdviceIsActionable(t *testing.T) {
	const message = "Attribute 'http.custom' extends an existing namespace"

	report := Report{
		Samples: []json.RawMessage{json.RawMessage(`{
			"span": {
				"live_check_result": {
					"all_advice": [{
						"id": "extends_namespace",
						"message": "Attribute 'http.custom' extends an existing namespace",
						"level": "information",
						"signal_type": "span",
						"signal_name": "GET /test"
					}]
				}
			}
		}`)},
		Statistics: Statistics{
			AdviceMessageCounts: map[string]int{message: 1},
		},
	}

	adviceByMsg := collectAdviceInfo(report.Samples)
	require.Equal(t, 1, countActionableAdvisories(&report.Statistics, adviceByMsg))
}
