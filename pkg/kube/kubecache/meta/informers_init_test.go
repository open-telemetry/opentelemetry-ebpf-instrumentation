// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func TestEnvironmentFiltering(t *testing.T) {
	vars := []v1.EnvVar{{Name: "A", Value: "B"}, {Value: "C"}, {}, {Name: "OTEL_SERVICE_NAME", Value: "service_name"}, {Name: "OTEL_RESOURCE_ATTRIBUTES", Value: "resource_attributes"}}

	filtered := envToMap(nil, metav1.ObjectMeta{}, vars)
	assert.Len(t, filtered, 2)

	serviceName, ok := filtered["OTEL_SERVICE_NAME"]
	assert.True(t, ok)
	assert.Equal(t, "service_name", serviceName)

	resourceAttrs, ok := filtered["OTEL_RESOURCE_ATTRIBUTES"]
	assert.True(t, ok)
	assert.Equal(t, "resource_attributes", resourceAttrs)
}

func testUnchangedImpl(t *testing.T, o1, o2 *informer.ObjectMeta, expected bool) {
	assert.Equal(t, expected, unchanged(o1, o2))
}

func TestUnchanged(t *testing.T) {
	type testData struct {
		name           string
		o1             informer.ObjectMeta
		o2             informer.ObjectMeta
		expectedResult bool
	}

	data := []testData{
		{
			"empty",
			informer.ObjectMeta{},
			informer.ObjectMeta{},
			true,
		},
		{
			"name",
			informer.ObjectMeta{
				Name: "meta",
			},
			informer.ObjectMeta{},
			true,
		},
		{
			"namespace",
			informer.ObjectMeta{
				Namespace: "default",
			},
			informer.ObjectMeta{},
			true,
		},
		{
			"labels",
			informer.ObjectMeta{
				Labels: map[string]string{"foo": "bar"},
			},
			informer.ObjectMeta{},
			false,
		},
		{
			"annotations",
			informer.ObjectMeta{
				Annotations: map[string]string{"foo": "bar"},
			},
			informer.ObjectMeta{},
			false,
		},
		{
			"nilpod",
			informer.ObjectMeta{
				Pod: nil,
			},
			informer.ObjectMeta{
				Pod: nil,
			},
			true,
		},
		{
			"zeropod",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			informer.ObjectMeta{
				Pod: nil,
			},
			false,
		},
		{
			"emptypod",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			true,
		},
		{
			"pod_uid",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Uid: "uid",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			false,
		},
		{
			"pod_uid_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Uid: "uid",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Uid: "uid",
				},
			},
			true,
		},
		{
			"pod_nodename",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "abacaxi",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "jabuticaba",
				},
			},
			false,
		},
		{
			"pod_nodename_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "abacaxi",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "abacaxi",
				},
			},
			true,
		},
		{
			"pod_startttime",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "12345",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "7890",
				},
			},
			false,
		},
		{
			"pod_startttime_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "12345",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "12345",
				},
			},
			true,
		},
		{
			"pod_hostip",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.1",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.2",
				},
			},
			false,
		},
		{
			"pod_hostip_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.1",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.1",
				},
			},
			true,
		},
		{
			"containers",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			false,
		},
		{
			"containers_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			true,
		},
		{
			"containers_nil",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						nil,
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						nil,
					},
				},
			},
			true,
		},
		{
			"containers_eq_not_nil",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						nil,
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			false,
		},
		{
			"containers_count",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
						{
							Id: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			false,
		},
		{
			"containers_count_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
						{
							Id: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
						{
							Id: "foo",
						},
					},
				},
			},
			true,
		},
		{
			"containers_name",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "bar",
						},
					},
				},
			},
			false,
		},
		{
			"containers_name_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "foo",
						},
					},
				},
			},
			true,
		},
		{
			"containers_env",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "not bar",
							},
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			false,
		},
		{
			"containers_env_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			true,
		},
	}

	for i := range data {
		d := &data[i]

		t.Run(d.name, func(t *testing.T) {
			testUnchangedImpl(t, &d.o1, &d.o2, d.expectedResult)
		})
	}
}
