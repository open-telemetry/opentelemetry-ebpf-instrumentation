// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"io"
	"log/slog"
	"sync"
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
	id      string
	events  chan *informer.Event
	entered chan struct{}
	release chan struct{}
}

func (o *eventObserver) ID() string {
	return o.id
}

func (o *eventObserver) On(event *informer.Event) error {
	if event.Resource.GetName() == "A" && o.release != nil {
		close(o.entered)
		<-o.release
	}
	o.events <- event
	return nil
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
	t.Cleanup(inf.Close)
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
	t.Cleanup(inf.Close)
	observer := &eventObserver{id: "observer", events: make(chan *informer.Event, 1)}
	inf.BaseNotifier.Subscribe(observer)

	handler := inf.ipInfoEventHandler(context.Background())
	staleTimestamp := time.Now().Add(-time.Hour).Unix()
	start := time.Now().Unix()

	cached := &indexableEntity{EncodedMeta: &informer.ObjectMeta{
		Name:            "pod",
		Kind:            typePod,
		StatusTimeEpoch: staleTimestamp,
	}}

	for _, object := range []any{cached, cache.DeletedFinalStateUnknown{Key: "pod", Obj: cached}} {
		handler.DeleteFunc(object)
		event := testutil.ReadChannel(t, observer.events, time.Second)
		assert.Equal(t, informer.EventType_DELETED, event.Type)
		assert.GreaterOrEqual(t, event.Resource.StatusTimeEpoch, start)
		assert.Equal(t, staleTimestamp, cached.EncodedMeta.StatusTimeEpoch)
		assert.NotSame(t, cached.EncodedMeta, event.Resource)
	}
}

func TestRefreshStatusTimeEpochPreservesCurrentTimestamp(t *testing.T) {
	em := &informer.ObjectMeta{StatusTimeEpoch: time.Now().Add(time.Hour).Unix()}

	refreshStatusTimeEpoch(em)

	assert.Greater(t, em.StatusTimeEpoch, time.Now().Unix())
}

func TestInformerSnapshotPrecedesConcurrentEvents(t *testing.T) {
	for _, liveType := range []informer.EventType{informer.EventType_DELETED, informer.EventType_UPDATED} {
		t.Run(liveType.String(), func(t *testing.T) {
			inf := &Informers{
				BaseNotifier: NewBaseNotifier(slog.Default()),
				log:          slog.Default(),
				config:       &informersConfig{disableNodes: true, disableServices: true},
				pods:         cache.NewSharedIndexInformer(&cache.ListWatch{}, &v1.Pod{}, 0, nil),
				waitForSync:  make(chan struct{}),
			}
			t.Cleanup(inf.Close)
			close(inf.waitForSync)
			for index, name := range []string{"A", "B"} {
				require.NoError(t, inf.pods.GetStore().Add(&indexableEntity{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					EncodedMeta: &informer.ObjectMeta{
						Name: name, Kind: typePod, StatusTimeEpoch: int64(index),
					},
				}))
			}

			observer := &eventObserver{
				id:      "observer",
				events:  make(chan *informer.Event, 4),
				entered: make(chan struct{}),
				release: make(chan struct{}),
			}
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(observer.release) }) })
			subscribed := make(chan struct{})
			go func() {
				inf.Subscribe(observer)
				close(subscribed)
			}()
			testutil.ReadChannel(t, observer.entered, time.Second)
			live := &informer.Event{
				Type:     liveType,
				Resource: &informer.ObjectMeta{Name: "B", Kind: typePod, StatusTimeEpoch: 2},
			}
			changed := &indexableEntity{ObjectMeta: metav1.ObjectMeta{Name: "B"}, EncodedMeta: live.Resource}
			if liveType == informer.EventType_DELETED {
				require.NoError(t, inf.pods.GetStore().Delete(changed))
			} else {
				require.NoError(t, inf.pods.GetStore().Update(changed))
			}
			inf.Notify(live)
			release.Do(func() { close(observer.release) })
			testutil.ReadChannel(t, subscribed, time.Second)

			for _, name := range []string{"A", "B"} {
				event := testutil.ReadChannel(t, observer.events, time.Second)
				assert.Equal(t, informer.EventType_CREATED, event.Type)
				assert.Equal(t, name, event.Resource.Name)
			}
			assert.Equal(t, informer.EventType_SYNC_FINISHED, testutil.ReadChannel(t, observer.events, time.Second).Type)
			assert.Same(t, live, testutil.ReadChannel(t, observer.events, time.Second))
		})
	}
}
