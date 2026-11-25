// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

type ISO8583AuthOutcome uint8

const (
	ISO8583Unknown ISO8583AuthOutcome = iota
	ISO8583Approved
	ISO8583PartiallyApproved
	ISO8583Declined
	ISO8583TechnicalError
	ISO8583NotApplicable
)

func (o ISO8583AuthOutcome) String() string {
	switch o {
	case ISO8583Approved:
		return "approved"
	case ISO8583PartiallyApproved:
		return "partially_approved"
	case ISO8583Declined:
		return "declined"
	case ISO8583TechnicalError:
		return "technical_error"
	case ISO8583NotApplicable:
		return "not_applicable"
	default:
		return "unknown"
	}
}

// ISO8583DurationSource identifies how the duration of an ISO 8583 span was obtained.
func (s *Span) ISO8583DurationSource() string {
	if s.Type != EventTypeISO8583Client && s.Type != EventTypeISO8583Server {
		return ""
	}
	if s.ISO8583Field7Timing {
		return "field_7"
	}
	return "capture"
}
