// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

type eventObserver struct {
	id     string
	events chan *informer.Event
}

func (o *eventObserver) ID() string {
	return o.id
}

func (o *eventObserver) On(event *informer.Event) error {
	o.events <- event
	return nil
}

func TestInformerSubscriptionOrdersSnapshotUpdatesAndSync(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pods := cache.NewSharedIndexInformer(&cache.ListWatch{}, &v1.Pod{}, 0, cache.Indexers{})
	require.NoError(t, pods.GetStore().Add(&indexableEntity{
		EncodedMeta: &informer.ObjectMeta{Name: "snapshot"},
	}))
	inf := &Informers{
		BaseNotifier: NewBaseNotifier(log),
		log:          log,
		config: &informersConfig{
			disableNodes:    true,
			disableServices: true,
		},
		pods:        pods,
		waitForSync: make(chan struct{}),
	}
	observer := &eventObserver{id: "observer", events: make(chan *informer.Event, 3)}

	inf.Subscribe(observer)
	inf.Notify(&informer.Event{
		Type:     informer.EventType_UPDATED,
		Resource: &informer.ObjectMeta{Name: "update"},
	})
	close(inf.waitForSync)

	snapshot := testutil.ReadChannel(t, observer.events, time.Second)
	assert.Equal(t, informer.EventType_CREATED, snapshot.Type)
	assert.Equal(t, "snapshot", snapshot.Resource.Name)
	update := testutil.ReadChannel(t, observer.events, time.Second)
	assert.Equal(t, informer.EventType_UPDATED, update.Type)
	assert.Equal(t, "update", update.Resource.Name)
	syncFinished := testutil.ReadChannel(t, observer.events, time.Second)
	assert.Equal(t, informer.EventType_SYNC_FINISHED, syncFinished.Type)
}

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

func TestIPInfoEventHandlerRefreshesUpdatedEventTimestamp(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	inf := &Informers{
		log:          log,
		BaseNotifier: NewBaseNotifier(log),
	}
	observer := &eventObserver{id: "observer", events: make(chan *informer.Event, 1)}
	inf.BaseNotifier.Subscribe(observer)

	handler := inf.ipInfoEventHandler(context.Background())
	staleTimestamp := time.Now().Add(-time.Hour).Unix()
	start := time.Now().Unix()

	handler.UpdateFunc(
		&indexableEntity{EncodedMeta: &informer.ObjectMeta{
			Name:            "pod",
			Kind:            typePod,
			StatusTimeEpoch: staleTimestamp,
			Labels:          map[string]string{"version": "old"},
		}},
		&indexableEntity{EncodedMeta: &informer.ObjectMeta{
			Name:            "pod",
			Kind:            typePod,
			StatusTimeEpoch: staleTimestamp,
			Labels:          map[string]string{"version": "new"},
		}},
	)

	event := testutil.ReadChannel(t, observer.events, time.Second)
	assert.Equal(t, informer.EventType_UPDATED, event.Type)
	assert.GreaterOrEqual(t, event.Resource.StatusTimeEpoch, start)
}

func TestIPInfoEventHandlerRefreshesDeletedEventTimestamp(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	inf := &Informers{
		log:          log,
		BaseNotifier: NewBaseNotifier(log),
	}
	observer := &eventObserver{id: "observer", events: make(chan *informer.Event, 1)}
	inf.BaseNotifier.Subscribe(observer)

	handler := inf.ipInfoEventHandler(context.Background())
	staleTimestamp := time.Now().Add(-time.Hour).Unix()
	start := time.Now().Unix()

	handler.DeleteFunc(&indexableEntity{EncodedMeta: &informer.ObjectMeta{
		Name:            "pod",
		Kind:            typePod,
		StatusTimeEpoch: staleTimestamp,
	}})

	event := testutil.ReadChannel(t, observer.events, time.Second)
	assert.Equal(t, informer.EventType_DELETED, event.Type)
	assert.GreaterOrEqual(t, event.Resource.StatusTimeEpoch, start)
}

func TestRefreshStatusTimeEpochPreservesCurrentTimestamp(t *testing.T) {
	em := &informer.ObjectMeta{StatusTimeEpoch: time.Now().Add(time.Hour).Unix()}

	refreshStatusTimeEpoch(em)

	assert.Greater(t, em.StatusTimeEpoch, time.Now().Unix())
}
