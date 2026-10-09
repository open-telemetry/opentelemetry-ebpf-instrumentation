// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

func TestGCERefresherPaginationAndInstanceLifecycle(t *testing.T) {
	const prefix = "/projects/test-project/zones/us-central1-a/"
	var pages atomic.Int64
	client := gceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var response any
		switch r.URL.Path {
		case prefix + "instanceGroupManagers":
			response = &compute.InstanceGroupManagerList{Items: []*compute.InstanceGroupManager{{Name: "storefront"}}}
		case prefix + "instanceGroupManagers/storefront/listManagedInstances":
			assert.Equal(t, http.MethodPost, r.Method)
			pages.Add(1)
			if r.URL.Query().Get("pageToken") == "" {
				response = &compute.InstanceGroupManagersListManagedInstancesResponse{
					ManagedInstances: []*compute.ManagedInstance{{Instance: prefix + "instances/live"}},
					NextPageToken:    "second-page",
				}
			} else {
				assert.Equal(t, "second-page", r.URL.Query().Get("pageToken"))
				response = &compute.InstanceGroupManagersListManagedInstancesResponse{
					ManagedInstances: []*compute.ManagedInstance{
						{Instance: prefix + "instances/stopped"},
						{Instance: prefix + "instances/deleted"},
					},
				}
			}
		case prefix + "instances/live":
			response = gceTestInstance(101, "10.0.0.1")
		case prefix + "instances/stopped":
			instance := gceTestInstance(102, "10.0.0.2")
			instance.Status = "TERMINATED"
			response = instance
		case prefix + "instances/deleted":
			http.NotFound(w, r)
			return
		default:
			t.Errorf("unexpected Compute request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	})
	refresher := NewGCERefresher(client, "test-project", "us-central1-a")
	snapshot := MetadataSnapshot{ServiceByIP: map[string]string{}, ServiceByInstanceID: map[string]string{}}
	require.NoError(t, refresher.Refresh(t.Context(), &snapshot))
	assert.Equal(t, int64(2), pages.Load())
	assert.Equal(t, map[string]string{"10.0.0.1": "storefront"}, snapshot.ServiceByIP)
	assert.Equal(t, map[string]string{"101": "storefront"}, snapshot.ServiceByInstanceID)
}

func TestGCEInventoryRefreshFailureAndReplacement(t *testing.T) {
	const prefix = "/projects/test-project/zones/us-central1-a/"
	var fail atomic.Bool
	var replacement atomic.Bool
	client := gceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var response any
		switch r.URL.Path {
		case prefix + "instanceGroupManagers":
			response = &compute.InstanceGroupManagerList{Items: []*compute.InstanceGroupManager{{Name: "checkout"}}}
		case prefix + "instanceGroupManagers/checkout/listManagedInstances":
			response = &compute.InstanceGroupManagersListManagedInstancesResponse{
				ManagedInstances: []*compute.ManagedInstance{{Instance: prefix + "instances/backend"}},
			}
		case prefix + "instances/backend":
			if fail.Load() {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			response = gceTestInstance(101, "10.0.0.1")
			if replacement.Load() {
				response = gceTestInstance(202, "10.0.0.2")
			}
		default:
			t.Errorf("unexpected Compute request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	})
	inventory := NewInventory([]MetadataRefresher{
		NewGCERefresher(client, "test-project", "us-central1-a"),
	})
	changes := inventory.SubscribeContainerChanges()
	readChange := func() {
		t.Helper()
		select {
		case change := <-changes:
			require.True(t, change.InstancesChanged)
		default:
			t.Fatal("successful refresh did not publish VM membership changes")
		}
	}
	inventory.refresh(t.Context())
	readChange()
	name, ok := inventory.ServiceNameForInstanceID("101")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)

	fail.Store(true)
	inventory.refresh(t.Context())
	name, ok = inventory.ServiceNameForIP("10.0.0.1")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)
	select {
	case change := <-changes:
		t.Fatalf("failed refresh published changes: %+v", change)
	default:
	}

	fail.Store(false)
	replacement.Store(true)
	inventory.refresh(t.Context())
	readChange()
	_, ok = inventory.ServiceNameForInstanceID("101")
	assert.False(t, ok)
	_, ok = inventory.ServiceNameForIP("10.0.0.1")
	assert.False(t, ok)
	name, ok = inventory.ServiceNameForInstanceID("202")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)
	name, ok = inventory.ServiceNameForIP("10.0.0.2")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)
}

func TestGCERefresherAmbiguousIP(t *testing.T) {
	const prefix = "/projects/test-project/zones/us-central1-a/"
	client := gceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var response any
		switch r.URL.Path {
		case prefix + "instanceGroupManagers":
			response = &compute.InstanceGroupManagerList{Items: []*compute.InstanceGroupManager{{Name: "storefront"}, {Name: "checkout"}}}
		case prefix + "instanceGroupManagers/storefront/listManagedInstances":
			response = &compute.InstanceGroupManagersListManagedInstancesResponse{
				ManagedInstances: []*compute.ManagedInstance{{Instance: prefix + "instances/frontend"}},
			}
		case prefix + "instanceGroupManagers/checkout/listManagedInstances":
			response = &compute.InstanceGroupManagersListManagedInstancesResponse{
				ManagedInstances: []*compute.ManagedInstance{{Instance: prefix + "instances/backend"}},
			}
		case prefix + "instances/frontend":
			response = gceTestInstance(101, "10.0.0.1")
		case prefix + "instances/backend":
			response = gceTestInstance(202, "10.0.0.1")
		default:
			t.Errorf("unexpected Compute request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	})
	refresher := NewGCERefresher(client, "test-project", "us-central1-a")
	snapshot := MetadataSnapshot{ServiceByIP: map[string]string{}, ServiceByInstanceID: map[string]string{}}
	require.NoError(t, refresher.Refresh(t.Context(), &snapshot))
	assert.Empty(t, snapshot.ServiceByIP)
	assert.Equal(t, map[string]string{"101": "storefront", "202": "checkout"}, snapshot.ServiceByInstanceID)
}

func TestGCEInventoryDiscoversGroupChanges(t *testing.T) {
	const prefix = "/projects/test-project/zones/us-central1-a/"
	var stage atomic.Int64
	client := gceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var response any
		switch r.URL.Path {
		case prefix + "instanceGroupManagers":
			assert.Equal(t, http.MethodGet, r.Method)
			switch stage.Load() {
			case 0:
				response = &compute.InstanceGroupManagerList{}
			case 1, 2:
				if r.URL.Query().Get("pageToken") == "" {
					response = &compute.InstanceGroupManagerList{Items: []*compute.InstanceGroupManager{{Name: "storefront"}}, NextPageToken: "next"}
				} else {
					assert.Equal(t, "next", r.URL.Query().Get("pageToken"))
					if stage.Load() == 2 {
						http.Error(w, "permission denied", http.StatusForbidden)
						return
					}
					response = &compute.InstanceGroupManagerList{Items: []*compute.InstanceGroupManager{{Name: "checkout"}}}
				}
			default:
				response = &compute.InstanceGroupManagerList{Items: []*compute.InstanceGroupManager{{Name: "checkout"}}}
			}
		case prefix + "instanceGroupManagers/storefront/listManagedInstances":
			response = &compute.InstanceGroupManagersListManagedInstancesResponse{ManagedInstances: []*compute.ManagedInstance{{Instance: prefix + "instances/frontend"}}}
		case prefix + "instanceGroupManagers/checkout/listManagedInstances":
			if stage.Load() == 4 {
				http.NotFound(w, r)
				return
			}
			response = &compute.InstanceGroupManagersListManagedInstancesResponse{ManagedInstances: []*compute.ManagedInstance{{Instance: prefix + "instances/backend"}}}
		case prefix + "instances/frontend":
			response = gceTestInstance(101, "10.0.0.1")
		case prefix + "instances/backend":
			response = gceTestInstance(202, "10.0.0.2")
		default:
			t.Errorf("unexpected Compute request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	})
	inventory := NewInventory([]MetadataRefresher{NewGCERefresher(client, "test-project", "us-central1-a")})
	check := func(ip, id, want string) {
		t.Helper()
		name, found := inventory.ServiceNameForIP(ip)
		assert.Equal(t, want != "", found)
		assert.Equal(t, want, name)
		name, found = inventory.ServiceNameForInstanceID(id)
		assert.Equal(t, want != "", found)
		assert.Equal(t, want, name)
	}
	inventory.refresh(t.Context())
	check("10.0.0.1", "101", "")

	// New groups appear without restarting or changing configuration.
	stage.Store(1)
	inventory.refresh(t.Context())
	check("10.0.0.1", "101", "storefront")
	check("10.0.0.2", "202", "checkout")

	// A failed later page must retain both entries from the prior snapshot.
	stage.Store(2)
	inventory.refresh(t.Context())
	check("10.0.0.1", "101", "storefront")
	check("10.0.0.2", "202", "checkout")

	stage.Store(3)
	inventory.refresh(t.Context())
	check("10.0.0.1", "101", "")
	check("10.0.0.2", "202", "checkout")

	// The last group disappears between enumeration and membership lookup.
	stage.Store(4)
	inventory.refresh(t.Context())
	check("10.0.0.2", "202", "")
}

func gceTestClient(t *testing.T, handler http.HandlerFunc) *compute.Service {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := compute.NewService(t.Context(),
		option.WithEndpoint(server.URL+"/"),
		option.WithHTTPClient(server.Client()),
		option.WithoutAuthentication(),
	)
	require.NoError(t, err)
	return client
}

func gceTestInstance(id uint64, ip string) *compute.Instance {
	return &compute.Instance{
		Id: id, Status: instanceStatusRunning,
		NetworkInterfaces: []*compute.NetworkInterface{{NetworkIP: ip}},
	}
}
