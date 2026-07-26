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

// TestUndefinedEnumVariantAdviceIsActionable exercises weaver's serialized
// finding ID so information-level out-of-enum values (e.g. an empty
// messaging.operation.type or an HTTP status leaking into a gRPC status
// attribute) cannot silently bypass semantic convention validation.
func TestUndefinedEnumVariantAdviceIsActionable(t *testing.T) {
	const message = "Enum value '200' is not defined in the registry"

	report := Report{
		Samples: []json.RawMessage{json.RawMessage(`{
			"span": {
				"live_check_result": {
					"all_advice": [{
						"id": "undefined_enum_variant",
						"message": "Enum value '200' is not defined in the registry",
						"level": "information",
						"signal_type": "span",
						"signal_name": "routeguide.RouteGuide/GetFeature"
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

// TestUndefinedEnumVariantEmptyValueIsActionable pins that an empty value on
// an enumerated attribute — always an emitter bug (the attribute must be
// omitted instead) — fails validation. Values OBI emits on purpose are
// declared in the registry override groups under schemas/obi/groups/ (see
// schemas/obi/README.md), so weaver itself accepts them and no finding is
// produced; anything weaver still flags is a bug by definition.
func TestUndefinedEnumVariantEmptyValueIsActionable(t *testing.T) {
	const message = "Enum attribute 'messaging.operation.type' has value '' which is not documented."

	report := Report{
		Samples: []json.RawMessage{json.RawMessage(`{
			"span": {
				"live_check_result": {
					"all_advice": [{
						"id": "undefined_enum_variant",
						"message": "Enum attribute 'messaging.operation.type' has value '' which is not documented.",
						"level": "information",
						"signal_type": "span",
						"signal_name": "publish"
					}]
				}
			}
		}`)},
		Statistics: Statistics{
			AdviceMessageCounts: map[string]int{message: 2},
		},
	}

	adviceByMsg := collectAdviceInfo(report.Samples)
	require.Equal(t, 2, countActionableAdvisories(&report.Statistics, adviceByMsg),
		"empty enum values are emitter bugs and must stay actionable")
}

// TestInformationAdviceWithoutActionableTypeIsNotCounted pins the inverse:
// information-level advice whose type is not in actionableAdviceTypes must
// not fail validation.
func TestInformationAdviceWithoutActionableTypeIsNotCounted(t *testing.T) {
	const message = "Attribute 'http.request.method' is deprecated, use ..."

	report := Report{
		Samples: []json.RawMessage{json.RawMessage(`{
			"span": {
				"live_check_result": {
					"all_advice": [{
						"id": "deprecated",
						"message": "Attribute 'http.request.method' is deprecated, use ...",
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
	require.Equal(t, 0, countActionableAdvisories(&report.Statistics, adviceByMsg))
}
