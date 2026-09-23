// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ecs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClient struct {
	taskARNs      []string
	tasksByARN    map[string]types.Task
	describeCalls int
	listStatus    types.DesiredStatus
	listError     error
}

func (f *fakeClient) ListTasks(_ context.Context, input *awsecs.ListTasksInput, _ ...func(*awsecs.Options)) (*awsecs.ListTasksOutput, error) {
	f.listStatus = input.DesiredStatus
	if f.listError != nil {
		return nil, f.listError
	}
	if input.NextToken == nil {
		middle := len(f.taskARNs) / 2
		return &awsecs.ListTasksOutput{TaskArns: f.taskARNs[:middle], NextToken: aws.String("next")}, nil
	}
	return &awsecs.ListTasksOutput{TaskArns: f.taskARNs[len(f.taskARNs)/2:]}, nil
}

func (f *fakeClient) DescribeTasks(_ context.Context, input *awsecs.DescribeTasksInput, _ ...func(*awsecs.Options)) (*awsecs.DescribeTasksOutput, error) {
	f.describeCalls++
	out := &awsecs.DescribeTasksOutput{}
	for _, arn := range input.Tasks {
		out.Tasks = append(out.Tasks, f.tasksByARN[arn])
	}
	return out, nil
}

func TestInventoryRefresh(t *testing.T) {
	client := &fakeClient{tasksByARN: map[string]types.Task{}}
	for index := range 101 {
		arn := fmt.Sprintf("task-%d", index)
		client.taskARNs = append(client.taskARNs, arn)
		client.tasksByARN[arn] = ecsServiceTask(fmt.Sprintf("10.0.0.%d", index+1), "service-a")
	}
	inventory := NewInventory(client, "cluster")

	require.NoError(t, inventory.Refresh(t.Context()))
	assert.Equal(t, types.DesiredStatusRunning, client.listStatus)
	assert.Equal(t, 2, client.describeCalls)
	name, ok := inventory.ServiceNameForIP("10.0.0.101")
	assert.True(t, ok)
	assert.Equal(t, "service-a", name)

	client.taskARNs = []string{"replacement"}
	client.tasksByARN = map[string]types.Task{
		"replacement": ecsServiceTask("10.1.0.1", "service-b"),
	}
	require.NoError(t, inventory.Refresh(t.Context()))
	_, ok = inventory.ServiceNameForIP("10.0.0.101")
	assert.False(t, ok)
	name, ok = inventory.ServiceNameForIP("10.1.0.1")
	assert.True(t, ok)
	assert.Equal(t, "service-b", name)
}

func TestInventorySkipsStandaloneTasks(t *testing.T) {
	client := &fakeClient{
		taskARNs: []string{"standalone"},
		tasksByARN: map[string]types.Task{
			"standalone": {
				Group:       aws.String("family:batch-job"),
				Attachments: taskAttachment("10.2.0.1"),
			},
		},
	}
	inventory := NewInventory(client, "cluster")

	require.NoError(t, inventory.Refresh(t.Context()))
	_, ok := inventory.ServiceNameForIP("10.2.0.1")
	assert.False(t, ok)
}

func TestInventoryContainerIdentity(t *testing.T) {
	firstID := strings.Repeat("a", 64)
	secondID := strings.Repeat("b", 64)
	standaloneID := strings.Repeat("c", 64)
	client := &fakeClient{
		taskARNs: []string{"service", "standalone"},
		tasksByARN: map[string]types.Task{
			"service": {
				Group: aws.String("service:checkout"),
				Containers: []types.Container{
					{RuntimeId: aws.String(firstID)},
					{RuntimeId: aws.String(secondID)},
					{RuntimeId: aws.String("")},
					{},
				},
			},
			"standalone": {
				Group:      aws.String("family:batch-job"),
				Containers: []types.Container{{RuntimeId: aws.String(standaloneID)}},
			},
		},
	}
	inventory := NewInventory(client, "cluster")
	require.NoError(t, inventory.Refresh(t.Context()))
	for _, id := range []string{firstID, secondID} {
		name, ok := inventory.ServiceNameForContainerID(id)
		assert.True(t, ok)
		assert.Equal(t, "checkout", name)
	}
	for _, id := range []string{"", firstID[:12], standaloneID} {
		_, ok := inventory.ServiceNameForContainerID(id)
		assert.False(t, ok)
	}

	client.taskARNs = []string{"replacement"}
	client.tasksByARN = map[string]types.Task{
		"replacement": {
			Group:      aws.String("service:payments"),
			Containers: []types.Container{{RuntimeId: aws.String(secondID)}},
		},
	}
	require.NoError(t, inventory.Refresh(t.Context()))
	_, ok := inventory.ServiceNameForContainerID(firstID)
	assert.False(t, ok)
	name, ok := inventory.ServiceNameForContainerID(secondID)
	assert.True(t, ok)
	assert.Equal(t, "payments", name)

	client.taskARNs = nil
	require.NoError(t, inventory.Refresh(t.Context()))
	_, ok = inventory.ServiceNameForContainerID(secondID)
	assert.False(t, ok)
}

func TestInventoryChanges(t *testing.T) {
	client := &fakeClient{listError: errors.New("unavailable")}
	inventory := NewInventory(client, "cluster")
	changes := inventory.Changes()
	require.Error(t, inventory.Refresh(t.Context()))
	select {
	case <-changes:
		t.Fatal("failed refresh published an update")
	default:
	}
	client.listError = nil
	require.NoError(t, inventory.Refresh(t.Context()))
	select {
	case <-changes:
	default:
		t.Fatal("successful refresh did not publish an update")
	}
	next := inventory.Changes()
	require.NotEqual(t, changes, next)
	select {
	case <-next:
		t.Fatal("next update channel is already closed")
	default:
	}
}

func ecsServiceTask(ip, name string) types.Task {
	return types.Task{
		Group:       aws.String("service:" + name),
		Attachments: taskAttachment(ip),
	}
}

func taskAttachment(ip string) []types.Attachment {
	return []types.Attachment{{
		Details: []types.KeyValuePair{{
			Name:  aws.String("privateIPv4Address"),
			Value: aws.String(ip),
		}},
	}}
}
