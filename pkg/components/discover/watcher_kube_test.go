package discover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/helpers/container"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/kube"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubecache/informer"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubecache/meta"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/obi"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/services"
)

const timeout = 5 * time.Second

const (
	namespace      = "test-ns"
	containerPID   = 123
	containerID    = "container-123"
	containerPort  = 332
	replicaSetName = "the-deployment-123456789"
	deploymentName = "the-deployment"
	podName        = "the-deployment-123456789-abcde"
)

func TestWatcherKubeEnricher(t *testing.T) {
	type event struct {
		fn           func(input *msg.Queue[[]Event[ProcessAttrs]], fInformer meta.Notifier)
		shouldNotify bool
	}
	type testCase struct {
		name  string
		steps []event
	}
	// test deployment functions
	process := func(input *msg.Queue[[]Event[ProcessAttrs]], _ meta.Notifier) {
		newProcess(input, containerPID, []uint32{containerPort})
	}
	pod := func(_ *msg.Queue[[]Event[ProcessAttrs]], fInformer meta.Notifier) {
		deployPod(fInformer, podName, containerID, nil)
	}
	ownedPod := func(_ *msg.Queue[[]Event[ProcessAttrs]], fInformer meta.Notifier) {
		deployOwnedPod(fInformer, namespace, podName, replicaSetName, deploymentName, containerID)
	}

	// The watcherKubeEnricher has to listen and relate information from multiple asynchronous sources.
	// Each test case verifies that whatever the order of the events is,
	testCases := []testCase{
		{name: "process-pod", steps: []event{{fn: process, shouldNotify: true}, {fn: ownedPod, shouldNotify: true}}},
		{name: "pod-process", steps: []event{{fn: ownedPod, shouldNotify: false}, {fn: process, shouldNotify: true}}},
		{name: "process-pod (no owner)", steps: []event{{fn: process, shouldNotify: true}, {fn: pod, shouldNotify: true}}},
		{name: "pod-process (no owner)", steps: []event{{fn: pod, shouldNotify: false}, {fn: process, shouldNotify: true}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			containerInfoForPID = fakeContainerInfo

			// Setup a fake K8s API connected to the watcherKubeEnricher
			fInformer := &fakeInformer{}
			store := kube.NewStore(fInformer, kube.ResourceLabels{}, nil)
			input := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
			defer input.Close()
			output := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
			outputCh := output.Subscribe()
			wkeNodeFunc, err := WatcherKubeEnricherProvider(&fakeMetadataProvider{store: store}, input, output)(t.Context())
			require.NoError(t, err)
			go wkeNodeFunc(t.Context())

			// deploy all the involved elements where the metadata are composed of
			// in different orders to test that watcherKubeEnricher will eventually handle everything
			var events []Event[ProcessAttrs]
			for _, step := range tc.steps {
				step.fn(input, fInformer)
				if step.shouldNotify {
					events = testutil.ReadChannel(t, outputCh, timeout)
				}
			}

			require.Len(t, events, 1)
			event := events[0]
			assert.Equal(t, EventCreated, event.Type)
			assert.EqualValues(t, containerPID, event.Obj.pid)
			assert.Equal(t, []uint32{containerPort}, event.Obj.openPorts)
			assert.Equal(t, namespace, event.Obj.metadata[services.AttrNamespace])
			assert.Equal(t, podName, event.Obj.metadata[services.AttrPodName])
			if strings.Contains(tc.name, "(no owner)") {
				assert.Empty(t, event.Obj.metadata[services.AttrReplicaSetName])
				assert.Empty(t, event.Obj.metadata[services.AttrDeploymentName])
			} else {
				assert.Equal(t, replicaSetName, event.Obj.metadata[services.AttrReplicaSetName])
				assert.Equal(t, deploymentName, event.Obj.metadata[services.AttrDeploymentName])
			}
		})
	}
}

func TestWatcherKubeEnricherWithMatcher(t *testing.T) {
	containerInfoForPID = fakeContainerInfo
	processInfo = fakeProcessInfo

	// Setup a fake K8s API connected to the watcherKubeEnricher
	fInformer := &fakeInformer{}
	store := kube.NewStore(fInformer, kube.ResourceLabels{}, nil)
	inputQueue := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	defer inputQueue.Close()
	connectQueue := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	outputQueue := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	outputCh := outputQueue.Subscribe()
	swi := swarm.Instancer{}
	swi.Add(WatcherKubeEnricherProvider(&fakeMetadataProvider{store: store}, inputQueue, connectQueue))

	pipeConfig := obi.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only
    namespace: foo
    open_ports: 80
  - name: metadata-only
    k8s_pod_name: chichi
  - name: both
    open_ports: 443
    k8s_deployment_name: chacha*
  - name: pod-label-only
    k8s_pod_labels:
      instrument: "beyla"
  - name: pod-multi-label-only
    k8s_pod_labels:
      instrument: "ebpf"
      lang: "go*"
  - name: pod-annotation-only
    k8s_pod_annotations:
      deploy.type: "canary"
  - name: pod-multi-annotation-only
    k8s_pod_annotations:
      deploy.type: "prod"
      version: "v[0-9]*"
`), &pipeConfig))

	swi.Add(CriteriaMatcherProvider(&pipeConfig, connectQueue, outputQueue))

	nodesRunner, err := swi.Instance(t.Context())
	require.NoError(t, err)

	nodesRunner.Start(t.Context())

	// sending some events that shouldn't match any of the above discovery criteria
	// so they won't be forwarded before any of later matched events
	newProcess(inputQueue, 123, []uint32{777})
	newProcess(inputQueue, 456, []uint32{})
	newProcess(inputQueue, 789, []uint32{443})
	deployOwnedPod(fInformer, namespace, "depl-rsid-podid", "depl-rsid", "depl", "container-789")

	// sending events that will match and will be forwarded
	t.Run("port-only match", func(t *testing.T) {
		newProcess(inputQueue, 12, []uint32{80})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "port-only", m.Obj.Criteria.GetName())
		assert.EqualValues(t, 12, m.Obj.Process.Pid)
	})

	t.Run("metadata-only match", func(t *testing.T) {
		newProcess(inputQueue, 34, []uint32{8080})
		deployPod(fInformer, "chichi", "container-34", nil)
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "metadata-only", m.Obj.Criteria.GetName())
		assert.EqualValues(t, 34, m.Obj.Process.Pid)
	})

	t.Run("pod-label-only match", func(t *testing.T) {
		newProcess(inputQueue, 42, []uint32{8080})
		deployPod(fInformer, "labeltest", "container-42", map[string]string{"instrument": "beyla"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-label-only", m.Obj.Criteria.GetName())
		assert.EqualValues(t, 42, m.Obj.Process.Pid)
	})

	t.Run("pod-multi-label-only match", func(t *testing.T) {
		newProcess(inputQueue, 43, []uint32{8080})
		deployPod(fInformer, "multi-labeltest", "container-43", map[string]string{"instrument": "ebpf", "lang": "golang"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-multi-label-only", m.Obj.Criteria.GetName())
		assert.EqualValues(t, 43, m.Obj.Process.Pid)
	})

	t.Run("pod-annotation-only match", func(t *testing.T) {
		newProcess(inputQueue, 44, []uint32{8080})
		deployPod(fInformer, "annotationtest", "container-44", nil, map[string]string{"deploy.type": "canary"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-annotation-only", m.Obj.Criteria.GetName())
		assert.EqualValues(t, 44, m.Obj.Process.Pid)
	})

	t.Run("pod-multi-annotation-only match", func(t *testing.T) {
		newProcess(inputQueue, 45, []uint32{8080})
		deployPod(fInformer, "multi-annotationtest", "container-45", nil, map[string]string{"deploy.type": "prod", "version": "v1"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-multi-annotation-only", m.Obj.Criteria.GetName())
		assert.EqualValues(t, 45, m.Obj.Process.Pid)
	})

	t.Run("both process and metadata match", func(t *testing.T) {
		newProcess(inputQueue, 56, []uint32{443})
		deployOwnedPod(fInformer, namespace, "chacha-rsid-podid", "chacha-rsid", "chacha", "container-56")
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "both", m.Obj.Criteria.GetName())
		assert.EqualValues(t, 56, m.Obj.Process.Pid)
	})

	t.Run("process deletion", func(t *testing.T) {
		inputQueue.Send([]Event[ProcessAttrs]{
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 123}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 456}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 789}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 1011}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 12}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 34}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 42}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 43}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 44}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 45}},
			{Type: EventDeleted, Obj: ProcessAttrs{pid: 56}},
		})
		// only forwards the deletion of the processes that were already matched
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 7)
		assert.Equal(t, EventDeleted, matches[0].Type)
		assert.EqualValues(t, 12, matches[0].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[1].Type)
		assert.EqualValues(t, 34, matches[1].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[2].Type)
		assert.EqualValues(t, 42, matches[2].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[3].Type)
		assert.EqualValues(t, 43, matches[3].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[4].Type)
		assert.EqualValues(t, 44, matches[4].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[5].Type)
		assert.EqualValues(t, 45, matches[5].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[6].Type)
		assert.EqualValues(t, 56, matches[6].Obj.Process.Pid)
	})
}

func TestWatcherKubeEnricherWithMultiPIDContainers(t *testing.T) {
	// Setup a fake K8s API connected to the watcherKubeEnricher
	fInformer := &fakeInformer{}
	store := kube.NewStore(fInformer, kube.ResourceLabels{}, nil)
	input := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10))
	outputCh := output.Subscribe()
	defer output.Close()

	wk := watcherKubeEnricher{
		log:                slog.With("component", "discover.watcherKubeEnricher"),
		store:              store,
		containerByPID:     map[PID]container.Info{},
		processByContainer: map[string][]ProcessAttrs{},
		podsInfoCh:         make(chan Event[*informer.ObjectMeta], 10),
		input:              input.Subscribe(),
		output:             output,
	}

	const containerAll = "container-contains-all"

	// Fake container info function that returns the same container string
	// for any PID we ask for
	containerInfoForPID = func(_ uint32) (container.Info, error) {
		return container.Info{ContainerID: containerAll}, nil
	}

	// Send two PID event, there will be no container information for them yet
	wk.enrichProcessEvent([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 2}},
	})

	events := testutil.ReadChannel(t, outputCh, timeout)

	assert.Len(t, events, 2)

	// Ensure we didn't add any container properties to these events, they should be as they were sent, not
	// enriched
	for _, event := range events {
		assert.Equal(t, Event[ProcessAttrs]{Type: EventCreated, Obj: ProcessAttrs{pid: event.Obj.pid}}, event)
	}

	podEvent := &informer.ObjectMeta{
		Name: "myservice", Namespace: namespace, Labels: map[string]string{"instrument": "ebpf", "lang": "golang"}, Annotations: map[string]string{"deploy.type": "prod"},
		Kind: "Pod",
		Pod: &informer.PodInfo{
			Containers: []*informer.ContainerInfo{{Id: containerAll}},
		},
	}

	// Let's add pod metadata now
	wk.enrichPodEvent(Event[*informer.ObjectMeta]{Type: EventCreated, Obj: podEvent})

	// We should see us notified about two matched processes, pid 1 and pid 2
	events = testutil.ReadChannel(t, outputCh, timeout)
	assert.Len(t, events, 2)

	for _, event := range events {
		assert.Equal(t, Event[ProcessAttrs]{
			Type: EventCreated,
			Obj: ProcessAttrs{
				pid: event.Obj.pid,
				metadata: map[string]string{
					"k8s_namespace":  "test-ns",
					"k8s_owner_name": "myservice",
					"k8s_pod_name":   "myservice",
				},
				podLabels: map[string]string{
					"instrument": "ebpf",
					"lang":       "golang",
				},
				podAnnotations: map[string]string{
					"deploy.type": "prod",
				},
			},
		}, event)
	}
}

func newProcess(input *msg.Queue[[]Event[ProcessAttrs]], pid PID, ports []uint32) {
	input.Send([]Event[ProcessAttrs]{{
		Type: EventCreated,
		Obj:  ProcessAttrs{pid: pid, openPorts: ports},
	}})
}

func deployPod(fInformer meta.Notifier, name, containerID string, labels map[string]string, annotations ...map[string]string) {
	var podAnnotations map[string]string
	if len(annotations) > 0 {
		podAnnotations = annotations[0]
	}
	fInformer.Notify(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: name, Namespace: namespace, Labels: labels, Annotations: podAnnotations,
			Kind: "Pod",
			Pod: &informer.PodInfo{
				Containers: []*informer.ContainerInfo{{Id: containerID}},
			},
		},
	})
}

func deployOwnedPod(fInformer meta.Notifier, ns, name, replicaSetName, deploymentName, containerID string) {
	fInformer.Notify(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: name, Namespace: ns,
			Kind: "Pod",
			Pod: &informer.PodInfo{
				Containers: []*informer.ContainerInfo{{Id: containerID}},
				Owners: []*informer.Owner{
					{Name: replicaSetName, Kind: "ReplicaSet"},
					{Name: deploymentName, Kind: "Deployment"},
				},
			},
		},
	})
}

func fakeContainerInfo(pid uint32) (container.Info, error) {
	return container.Info{ContainerID: fmt.Sprintf("container-%d", pid)}, nil
}

func fakeProcessInfo(pp ProcessAttrs) (*services.ProcessInfo, error) {
	return &services.ProcessInfo{
		Pid:       int32(pp.pid),
		OpenPorts: pp.openPorts,
		ExePath:   fmt.Sprintf("/bin/process%d", pp.pid),
	}, nil
}

type fakeMetadataProvider struct {
	store *kube.Store
}

func (i *fakeMetadataProvider) IsKubeEnabled() bool { return true }

func (i *fakeMetadataProvider) Get(_ context.Context) (*kube.Store, error) {
	return i.store, nil
}

type fakeInformer struct {
	mt        sync.Mutex
	observers map[string]meta.Observer
}

func (f *fakeInformer) Subscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	if f.observers == nil {
		f.observers = map[string]meta.Observer{}
	}
	f.observers[observer.ID()] = observer
}

func (f *fakeInformer) Unsubscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	delete(f.observers, observer.ID())
}

func (f *fakeInformer) Notify(event *informer.Event) {
	f.mt.Lock()
	defer f.mt.Unlock()
	for _, observer := range f.observers {
		_ = observer.On(event)
	}
}
