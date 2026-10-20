// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/internal/test/tools/img"
)

const imgFloci = img.Docker("floci/floci:2.2.0@sha256:e97cd0c1dc2aa14e7697fb5ef5018404c4d6345169dbd276315f0bed2c7b0520")

func setupFloci(t *testing.T, network dockertest.Network) string {
	t.Helper()
	mock, err := dockerPool.Run(t.Context(), imgFloci.Repository(),
		dockertest.WithTag(imgFloci.Tag()),
		dockertest.WithName(fmt.Sprintf("floci-%d", time.Now().UnixNano())),
		dockertest.WithPortBindings(portBindings("4566/tcp", "")),
		dockertest.WithContainerConfig(func(cfg *container.Config) { cfg.ExposedPorts = exposedPorts("4566/tcp") }),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, mock.Close(context.Background())) })
	_, err = dockerPool.Client().NetworkConnect(t.Context(), network.ID(), client.NetworkConnectOptions{
		Container: mock.ID(), EndpointConfig: endpointAliases("floci"),
	})
	require.NoError(t, err)
	return "http://" + mock.GetHostPort("4566/tcp")
}

func TestRoute53ServiceResolution(t *testing.T) {
	network := setupDockerNetwork(t)
	setupAWSMockIMDS(t, network)
	endpoint := setupFloci(t, network)
	r53 := route53.NewFromConfig(aws.Config{
		Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
	}, func(o *route53.Options) { o.BaseEndpoint = &endpoint })
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := r53.ListHostedZones(t.Context(), &route53.ListHostedZonesInput{})
		assert.NoError(ct, err)
	}, testTimeout, time.Second)
	zone, err := r53.CreateHostedZone(t.Context(), &route53.CreateHostedZoneInput{
		Name: aws.String("internal.example.com"), CallerReference: aws.String(t.Name()),
		HostedZoneConfig: &types.HostedZoneConfig{PrivateZone: true},
		VPC:              &types.VPC{VPCId: aws.String("vpc-d295a6a7"), VPCRegion: types.VPCRegionUsEast1},
	})
	require.NoError(t, err)
	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	_, ip := setupAWSResolverApplication(t, network, "ecs-backend", false)
	setupAWSResolverApplication(t, network, "ecs-frontend", true)
	record := types.ResourceRecordSet{
		Name: aws.String("payments.internal.example.com."), Type: types.RRTypeA, TTL: aws.Int64(60),
		ResourceRecords: []types.ResourceRecord{{Value: &ip}},
	}
	change := func(action types.ChangeAction, record types.ResourceRecordSet) {
		t.Helper()
		_, err := r53.ChangeResourceRecordSets(t.Context(), &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: zone.HostedZone.Id,
			ChangeBatch:  &types.ChangeBatch{Changes: []types.Change{{Action: action, ResourceRecordSet: &record}}},
		})
		require.NoError(t, err)
	}
	change(types.ChangeActionCreate, record)
	for name, vpc := range map[string]*types.VPC{
		"public.example.com":    nil,
		"unrelated.example.com": {VPCId: aws.String("vpc-unrelated"), VPCRegion: types.VPCRegionUsEast1},
	} {
		other, err := r53.CreateHostedZone(t.Context(), &route53.CreateHostedZoneInput{
			Name: aws.String(name), CallerReference: aws.String(t.Name() + name),
			HostedZoneConfig: &types.HostedZoneConfig{PrivateZone: vpc != nil}, VPC: vpc,
		})
		require.NoError(t, err)
		conflicting := record
		conflicting.Name = aws.String("a." + name + ".")
		_, err = r53.ChangeResourceRecordSets(t.Context(), &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: other.HostedZone.Id,
			ChangeBatch:  &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionCreate, ResourceRecordSet: &conflicting}}},
		})
		require.NoError(t, err)
	}
	o := obi{Env: []string{
		"AWS_ENDPOINT_URL_ROUTE_53=http://floci:4566", "AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test",
		"AWS_EC2_METADATA_SERVICE_ENDPOINT=http://mock-imds:80",
	}, Logs: createLogOutput(t, "route53-resolver")}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, "obi-config-route53.yml")
	pq := promtest.Client{HostPort: prometheusHostPort}
	httpClient := &http.Client{Timeout: time.Second}
	checkName := func(name string) {
		t.Helper()
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := httpClient.Get("http://localhost:8080/")
			require.NoError(ct, err)
			require.NoError(ct, resp.Body.Close())
			require.Equal(ct, http.StatusOK, resp.StatusCode)
			results, err := pq.Query(fmt.Sprintf(`http_client_request_duration_seconds_count{service_name="frontend",server=%q,server_address="ecs-backend"}`, name))
			require.NoError(ct, err)
			assert.NotEmpty(ct, results)
		}, testTimeout, 100*time.Millisecond)
	}
	checkName("payments.internal.example.com")
	change(types.ChangeActionDelete, record)
	record.Name = aws.String("checkout.internal.example.com.")
	change(types.ChangeActionCreate, record)
	checkName("checkout.internal.example.com")
}
