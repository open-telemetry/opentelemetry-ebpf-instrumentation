// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

type snsResult struct {
	TopicARN   string `json:"TopicArn"`
	MessageID  string `json:"MessageId"`
	Successful []struct {
		MessageID string `json:"MessageId"`
	} `json:"Successful"`
	Failed []json.RawMessage `json:"Failed"`
}

func testPythonAWSSNS(t *testing.T) {
	waitAWSProxy(t)
	waitForTestComponentsNoMetrics(t, localstackAddress)

	topic := snsRequest(t, "/createtopic")
	require.NotEmpty(t, topic.TopicARN)
	query := "?topic_arn=" + url.QueryEscape(topic.TopicARN)
	published := snsRequest(t, "/publish"+query)
	require.NotEmpty(t, published.MessageID)
	batch := snsRequest(t, "/publishbatch"+query)
	require.Len(t, batch.Successful, 2)
	require.Empty(t, batch.Failed)
	snsRequest(t, "/gettopicattributes"+query)
	snsRequest(t, "/deletetopic"+query)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, op := range []string{"CreateTopic", "Publish", "PublishBatch", "GetTopicAttributes", "DeleteTopic"} {
			span := fetchAWSSpanByOP(ct, "sns."+op)
			for key, expected := range map[string]any{
				"messaging.system":           "aws.sns",
				"messaging.operation.name":   op,
				"messaging.destination.name": "obi-topic",
				"aws.sns.topic.arn":          topic.TopicARN,
				"cloud.region":               "us-east-1",
			} {
				tag, found := jaeger.FindIn(span.Tags, key)
				require.True(ct, found, key)
				require.Equal(ct, expected, tag.Value, key)
			}
			tag, found := jaeger.FindIn(span.Tags, "aws.request_id")
			require.True(ct, found)
			require.NotEmpty(ct, tag.Value)
			tag, found = jaeger.FindIn(span.Tags, "messaging.operation.type")
			if op == "Publish" || op == "PublishBatch" {
				require.True(ct, found)
				require.Equal(ct, "send", tag.Value)
			} else {
				require.False(ct, found)
			}
			tag, found = jaeger.FindIn(span.Tags, "messaging.message.id")
			if op == "Publish" {
				require.True(ct, found)
				require.Equal(ct, published.MessageID, tag.Value)
			} else {
				require.False(ct, found)
			}
			tag, found = jaeger.FindIn(span.Tags, "messaging.batch.message_count")
			if op == "PublishBatch" {
				require.True(ct, found)
				require.EqualValues(ct, 2, tag.Value)
			} else {
				require.False(ct, found)
			}
		}
	}, testTimeout, time.Second)
}

func snsRequest(t *testing.T, path string) snsResult {
	t.Helper()
	resp, err := http.Get(awsProxyAddress + path)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result snsResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}
