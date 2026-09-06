// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsMessagingClientOperation(t *testing.T) {
	for _, tt := range []struct {
		name          string
		subType       int
		aws           *AWS
		wantMessaging bool
	}{
		{
			name:          "SendMessage is a producer operation",
			subType:       HTTPSubtypeAWSSQS,
			aws:           &AWS{SQS: AWSSQS{OperationType: MessagingSend}},
			wantMessaging: true,
		},
		{
			name:          "ReceiveMessage is a consumer operation",
			subType:       HTTPSubtypeAWSSQS,
			aws:           &AWS{SQS: AWSSQS{OperationType: MessagingReceive}},
			wantMessaging: true,
		},
		{
			name:          "DeleteMessage settles a consumed message",
			subType:       HTTPSubtypeAWSSQS,
			aws:           &AWS{SQS: AWSSQS{OperationType: MessagingSettle}},
			wantMessaging: true,
		},
		{
			name:    "queue administration is not a messaging client operation",
			subType: HTTPSubtypeAWSSQS,
			aws:     &AWS{SQS: AWSSQS{OperationType: ""}},
		},
		{
			name:    "other AWS subtypes are not messaging",
			subType: HTTPSubtypeAWSS3,
			aws:     &AWS{SQS: AWSSQS{OperationType: MessagingSend}},
		},
		{
			name:    "missing AWS payload is not messaging",
			subType: HTTPSubtypeAWSSQS,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			span := &Span{Type: EventTypeHTTPClient, SubType: tt.subType, AWS: tt.aws}
			assert.Equal(t, tt.wantMessaging, IsMessagingClientOperation(span))
		})
	}
}

func TestInferredSQSOperationTypesAreSemconvMembers(t *testing.T) {
	// messaging.operation.type is a semconv enum: every value OBI infers must
	// be one of its members, or the attribute is invalid on export.
	members := map[string]bool{
		"create": true, "send": true, "receive": true, "process": true, "settle": true,
	}
	for _, opType := range []string{MessagingSend, MessagingReceive, MessagingSettle} {
		assert.True(t, members[opType], opType)
	}
}
