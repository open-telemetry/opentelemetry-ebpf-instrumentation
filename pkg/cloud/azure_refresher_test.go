// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const azureTestSubscription = "11111111-1111-1111-1111-111111111111"

type azureTestCredential struct{}

func (azureTestCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type azureTestTransport struct{ handler http.HandlerFunc }

func (t azureTestTransport) Do(request *http.Request) (*http.Response, error) {
	response := httptest.NewRecorder()
	t.handler(response, request)
	return response.Result(), nil
}

func newAzureTestRefresher(t *testing.T, handler http.HandlerFunc) *AzureInventoryRefresher {
	t.Helper()
	options := &arm.ClientOptions{
		DisableRPRegistration: true,
		ClientOptions: azcore.ClientOptions{
			Transport: azureTestTransport{handler: handler},
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
	}
	compute, err := armcompute.NewClientFactory(azureTestSubscription, azureTestCredential{}, options)
	require.NoError(t, err)
	network, err := armnetwork.NewInterfacesClient(azureTestSubscription, azureTestCredential{}, options)
	require.NoError(t, err)
	return NewAzureRefresher(compute, network, azureTestSubscription, "services")
}

func TestAzureListScaleSets(t *testing.T) {
	const resourcePath = "/subscriptions/" + azureTestSubscription + "/resourceGroups/services/providers/Microsoft.Compute/virtualMachineScaleSets"
	const nextLink = "https://management.azure.com" + resourcePath + "?api-version=2026-04-01&$skiptoken=next"
	firstPage := fmt.Sprintf(`{"value":[{"name":"checkout","id":%q}],"nextLink":%q}`, resourcePath+"/checkout", nextLink)
	for _, tc := range []struct {
		name       string
		pages      []string
		lastStatus int
		wantNames  []string
		wantError  string
	}{
		{
			name: "all pages",
			pages: []string{
				firstPage,
				fmt.Sprintf(`{"value":[{"name":"payments","id":%q}]}`, resourcePath+"/payments"),
			},
			wantNames: []string{"checkout", "payments"},
		},
		{name: "empty", pages: []string{`{"value":[]}`}},
		{
			name: "later page fails", pages: []string{firstPage, `{"error":{"code":"AuthorizationFailed","message":"denied"}}`},
			lastStatus: http.StatusForbidden, wantError: "listing Azure scale sets",
		},
		{name: "missing name", pages: []string{`{"value":[{"id":"resource-id"}]}`}, wantError: "has no name or resource ID"},
		{name: "missing ID", pages: []string{`{"value":[{"name":"checkout"}]}`}, wantError: "has no name or resource ID"},
		{name: "null entry", pages: []string{`{"value":[null]}`}, wantError: "has no name or resource ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "management.azure.com", r.URL.Host)
				assert.Equal(t, resourcePath, r.URL.Path)
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				if calls > 0 {
					assert.Equal(t, "next", r.URL.Query().Get("$skiptoken"))
				}
				if !assert.Less(t, calls, len(tc.pages), "unexpected SDK request") {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if calls == len(tc.pages)-1 && tc.lastStatus != 0 {
					w.WriteHeader(tc.lastStatus)
				}
				_, _ = fmt.Fprint(w, tc.pages[calls])
				calls++
			})
			sets, err := refresher.listScaleSets(t.Context())
			assert.Equal(t, len(tc.pages), calls)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				assert.Nil(t, sets, "a failed enumeration must not return partial results")
				return
			}
			require.NoError(t, err)
			var names []string
			for _, set := range sets {
				names = append(names, *set.Name)
			}
			assert.Equal(t, tc.wantNames, names)
		})
	}
}

func TestAzureRunningUniformVMs(t *testing.T) {
	const resourcePath = "/subscriptions/" + azureTestSubscription + "/resourceGroups/services/providers/Microsoft.Compute/virtualMachineScaleSets/checkout/virtualMachines"
	for _, failSecondPage := range []bool{false, true} {
		t.Run(fmt.Sprintf("second page fails=%t", failSecondPage), func(t *testing.T) {
			calls := 0
			refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, resourcePath, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				if calls == 1 {
					assert.Equal(t, "instanceView", r.URL.Query().Get("$expand"))
					_, _ = fmt.Fprintf(w, `{"value":[
						{"instanceId":"0","properties":{"instanceView":{"statuses":[{"code":"PowerState/running"}]}}},
						{"instanceId":"1","properties":{"instanceView":{"statuses":[{"code":"PowerState/deallocated"}]}}},
						{"instanceId":"2","properties":{"instanceView":{"statuses":[{"code":"ProvisioningState/succeeded"}]}}},
						{"instanceId":"3","properties":{}},
						{"instanceId":"4","properties":{"instanceView":{"statuses":[null,{}]}}}
					],"nextLink":%q}`, "https://management.azure.com"+resourcePath+"?api-version=2026-04-01&$skiptoken=next")
					return
				}
				if !assert.Equal(t, 2, calls) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				assert.Equal(t, "next", r.URL.Query().Get("$skiptoken"))
				if failSecondPage {
					w.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprint(w, `{"error":{"code":"AuthorizationFailed","message":"denied"}}`)
					return
				}
				_, _ = fmt.Fprint(w, `{"value":[{"instanceId":"5","properties":{"instanceView":{"statuses":[{"code":"ProvisioningState/succeeded"},{"code":"PowerState/running"}]}}}]}`)
			})
			members, err := refresher.runningUniformVMs(t.Context(), "checkout")
			assert.Equal(t, 2, calls)
			if failSecondPage {
				require.ErrorContains(t, err, "listing Azure scale set")
				assert.Nil(t, members)
				return
			}
			require.NoError(t, err)
			require.Len(t, members, 2)
			assert.Equal(t, "0", *members[0].InstanceID)
			assert.Equal(t, "5", *members[1].InstanceID)
		})
	}
}

func TestAzureListUniformNICs(t *testing.T) {
	const resourcePath = "/subscriptions/" + azureTestSubscription + "/resourceGroups/services/providers/Microsoft.Compute/virtualMachineScaleSets/checkout/networkInterfaces"
	for _, failSecondPage := range []bool{false, true} {
		t.Run(fmt.Sprintf("second page fails=%t", failSecondPage), func(t *testing.T) {
			calls := 0
			refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, resourcePath, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				if calls == 1 {
					_, _ = fmt.Fprintf(w, `{"value":[{"name":"first"}],"nextLink":%q}`,
						"https://management.azure.com"+resourcePath+"?api-version=2018-10-01&$skiptoken=next")
					return
				}
				if !assert.Equal(t, 2, calls) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				assert.Equal(t, "next", r.URL.Query().Get("$skiptoken"))
				if failSecondPage {
					w.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprint(w, `{"error":{"code":"AuthorizationFailed","message":"denied"}}`)
					return
				}
				_, _ = fmt.Fprint(w, `{"value":[{"name":"second"}]}`)
			})
			interfaces, err := refresher.listUniformNICs(t.Context(), "checkout")
			assert.Equal(t, 2, calls)
			if failSecondPage {
				require.ErrorContains(t, err, "network interfaces")
				assert.Nil(t, interfaces)
				return
			}
			require.NoError(t, err)
			require.Len(t, interfaces, 2)
			assert.Equal(t, "first", *interfaces[0].Name)
			assert.Equal(t, "second", *interfaces[1].Name)
		})
	}
}

func TestAzureUniformVMs(t *testing.T) {
	const vmPath = "/subscriptions/" + azureTestSubscription + "/resourceGroups/services/providers/Microsoft.Compute/virtualMachineScaleSets/checkout/virtualMachines/0"
	for _, tc := range []struct {
		name        string
		uuid        string
		address     string
		failNetwork bool
		wantError   string
	}{
		{name: "join running VM interfaces", uuid: "vm-uuid", address: "::ffff:10.0.0.1"},
		{name: "missing UUID", address: "10.0.0.1", wantError: "no resource ID or UUID"},
		{name: "invalid address", uuid: "vm-uuid", address: "invalid", wantError: "invalid Azure private IP"},
		{name: "network API failure", uuid: "vm-uuid", failNetwork: true, wantError: "network interfaces"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/virtualMachines"):
					_, _ = fmt.Fprintf(w, `{"value":[
						{"id":%q,"properties":{"vmId":%q,"instanceView":{"statuses":[{"code":"PowerState/running"}]}}},
						{"id":%q,"properties":{"vmId":"stopped-uuid","instanceView":{"statuses":[{"code":"PowerState/stopped"}]}}}
					]}`, vmPath, tc.uuid, vmPath+"-stopped")
				case strings.HasSuffix(r.URL.Path, "/networkInterfaces"):
					if tc.failNetwork {
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, `{"error":{"code":"AuthorizationFailed","message":"denied"}}`)
						return
					}
					_, _ = fmt.Fprintf(w, `{"value":[
						{"properties":{"virtualMachine":{"id":%q},"ipConfigurations":[
							{"properties":{"privateIPAddress":%q}},
							{"properties":{"privateIPAddress":"2001:0db8:0:0::1"}},
							{"properties":{}},null
						]}},
						{"properties":{"virtualMachine":{"id":%q},"ipConfigurations":[{"properties":{"privateIPAddress":"10.0.0.2"}}]}},
						{"properties":{"virtualMachine":{"id":%q},"ipConfigurations":[{"properties":{"privateIPAddress":"10.0.0.99"}}]}},
						{"properties":{}}
					]}`, strings.ToUpper(vmPath), tc.address, vmPath, vmPath+"-stopped")
				default:
					t.Errorf("unexpected SDK request: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			vms, err := refresher.uniformVMs(t.Context(), "checkout")
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				assert.Nil(t, vms)
				return
			}
			require.NoError(t, err)
			require.Len(t, vms, 1)
			assert.Equal(t, "vm-uuid", vms[0].uuid)
			assert.ElementsMatch(t, []string{"10.0.0.1", "2001:db8::1", "10.0.0.2"}, vms[0].privateIPs)
		})
	}
}

type azureTestGroup struct {
	name   string
	mode   string
	uuid   string
	ips    []string
	status int
}

func azureInventoryHandler(t *testing.T, groups *[]azureTestGroup) http.HandlerFunc {
	t.Helper()
	const base = "/subscriptions/" + azureTestSubscription + "/resourceGroups/services/providers/Microsoft.Compute/virtualMachineScaleSets"
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.Equal(t, http.MethodGet, r.Method)
		var values []map[string]any
		if r.URL.Path == base {
			for _, group := range *groups {
				mode := group.mode
				if mode == "" {
					mode = "Uniform"
				}
				values = append(values, map[string]any{
					"name": group.name, "id": base + "/" + group.name,
					"properties": map[string]any{"orchestrationMode": mode},
				})
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"value": values}); err != nil {
				t.Errorf("encoding scale sets: %v", err)
			}
			return
		}
		for _, group := range *groups {
			flexible := group.mode == "Flexible"
			vmPath := base + "/" + group.name + "/virtualMachines"
			nicPath := base + "/" + group.name + "/networkInterfaces"
			if flexible {
				vmPath = strings.TrimSuffix(base, "/virtualMachineScaleSets") + "/virtualMachines"
				nicPath = "/subscriptions/" + azureTestSubscription + "/resourceGroups/networking/providers/Microsoft.Network/networkInterfaces/" + group.name
				if r.URL.Path == vmPath && r.URL.Query().Get("$filter") != "'virtualMachineScaleSet/id' eq '"+base+"/"+group.name+"'" {
					continue
				}
			}
			if !strings.EqualFold(r.URL.Path, vmPath) && !strings.EqualFold(r.URL.Path, nicPath) {
				continue
			}
			if group.status != 0 {
				w.WriteHeader(group.status)
				_, _ = fmt.Fprint(w, `{"error":{"code":"TestError","message":"unavailable"}}`)
				return
			}
			vmID := vmPath + "/" + group.name + "-0"
			switch {
			case strings.EqualFold(r.URL.Path, vmPath):
				assert.Equal(t, "instanceView", r.URL.Query().Get("$expand"))
				values = append(values, map[string]any{"id": vmID, "properties": map[string]any{
					"virtualMachineScaleSet": map[string]string{"id": base + "/" + group.name},
					"networkProfile":         map[string]any{"networkInterfaces": []any{map[string]string{"id": nicPath}}},
					"vmId":                   group.uuid, "instanceView": map[string]any{
						"statuses": []map[string]string{{"code": "PowerState/running"}},
					},
				}})
			case strings.EqualFold(r.URL.Path, nicPath):
				var configurations []map[string]any
				for _, ip := range group.ips {
					configurations = append(configurations, map[string]any{"properties": map[string]string{"privateIPAddress": ip}})
				}
				values = append(values, map[string]any{"properties": map[string]any{
					"virtualMachine": map[string]string{"id": vmID}, "ipConfigurations": configurations,
				}})
			default:
				t.Errorf("unexpected SDK request: %s", r.URL.Path)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var response any = map[string]any{"value": values}
			if flexible && r.URL.Path == nicPath {
				response = values[0]
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("encoding scale set resources: %v", err)
			}
			return
		}
		t.Errorf("unexpected SDK request: %s", r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestAzureInventoryMixedScaleSets(t *testing.T) {
	groups := []azureTestGroup{
		{name: "flexible", mode: "Flexible", uuid: "vm-b", ips: []string{"10.0.0.2"}},
		{name: "checkout", uuid: "vm-a", ips: []string{"10.0.0.1"}},
	}
	refresher := newAzureTestRefresher(t, azureInventoryHandler(t, &groups))
	snapshot := MetadataSnapshot{ServiceByIP: map[string]string{}, ServiceByInstanceID: map[string]string{}}
	require.NoError(t, refresher.Refresh(t.Context(), &snapshot))
	assert.Equal(t, map[string]string{"10.0.0.1": "checkout", "10.0.0.2": "flexible"}, snapshot.ServiceByIP)
	assert.Equal(t, map[string]string{
		AzureInstanceID(azureTestSubscription, "vm-a"): "checkout",
		AzureInstanceID(azureTestSubscription, "vm-b"): "flexible",
	}, snapshot.ServiceByInstanceID)
}

func TestAzureInventoryRefreshLifecycle(t *testing.T) {
	groups := []azureTestGroup{
		{name: "checkout", mode: "Flexible", uuid: "vm-a", ips: []string{"10.0.0.1"}},
		{name: "payments", uuid: "vm-b", ips: []string{"10.0.0.2"}},
	}
	refresher := newAzureTestRefresher(t, azureInventoryHandler(t, &groups))
	inventory := NewInventory([]MetadataRefresher{refresher})
	inventory.refresh(t.Context())
	name, ok := inventory.ServiceNameForInstanceID(AzureInstanceID(azureTestSubscription, "vm-a"))
	require.True(t, ok)
	assert.Equal(t, "checkout", name)

	groups[0].name = "renamed"
	groups[0].ips = []string{"10.0.0.3"}
	groups[1].status = http.StatusForbidden
	inventory.refresh(t.Context())
	name, ok = inventory.ServiceNameForIP("10.0.0.1")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)
	_, ok = inventory.ServiceNameForIP("10.0.0.3")
	assert.False(t, ok, "a later group failure must discard earlier results")
	name, ok = inventory.ServiceNameForInstanceID(AzureInstanceID(azureTestSubscription, "vm-a"))
	require.True(t, ok)
	assert.Equal(t, "checkout", name)

	groups[1].status = 0
	inventory.refresh(t.Context())
	_, ok = inventory.ServiceNameForIP("10.0.0.1")
	assert.False(t, ok)
	name, ok = inventory.ServiceNameForIP("10.0.0.3")
	require.True(t, ok)
	assert.Equal(t, "renamed", name)
	name, ok = inventory.ServiceNameForInstanceID(AzureInstanceID(azureTestSubscription, "vm-a"))
	require.True(t, ok)
	assert.Equal(t, "renamed", name)

	groups[1].status = http.StatusNotFound
	inventory.refresh(t.Context())
	_, ok = inventory.ServiceNameForIP("10.0.0.2")
	assert.False(t, ok)
	_, ok = inventory.ServiceNameForInstanceID(AzureInstanceID(azureTestSubscription, "vm-b"))
	assert.False(t, ok)
	name, ok = inventory.ServiceNameForIP("10.0.0.3")
	require.True(t, ok)
	assert.Equal(t, "renamed", name)

	groups = nil
	inventory.refresh(t.Context())
	_, ok = inventory.ServiceNameForIP("10.0.0.3")
	assert.False(t, ok)
	_, ok = inventory.ServiceNameForInstanceID(AzureInstanceID(azureTestSubscription, "vm-a"))
	assert.False(t, ok)
}

func TestAzureInventoryOverlappingIPs(t *testing.T) {
	groups := []azureTestGroup{
		{name: "checkout", uuid: "vm-a", ips: []string{"10.0.0.1", "10.0.0.2", "10.0.0.2"}},
		{name: "payments", mode: "Flexible", uuid: "vm-b", ips: []string{"::ffff:10.0.0.1"}},
		{name: "shipping", uuid: "vm-c", ips: []string{"10.0.0.1"}},
	}
	refresher := newAzureTestRefresher(t, azureInventoryHandler(t, &groups))
	snapshot := MetadataSnapshot{ServiceByIP: map[string]string{}, ServiceByInstanceID: map[string]string{}}
	require.NoError(t, refresher.Refresh(t.Context(), &snapshot))
	assert.Equal(t, map[string]string{"10.0.0.2": "checkout"}, snapshot.ServiceByIP)
	assert.Equal(t, map[string]string{
		AzureInstanceID(azureTestSubscription, "vm-a"): "checkout",
		AzureInstanceID(azureTestSubscription, "vm-b"): "payments",
		AzureInstanceID(azureTestSubscription, "vm-c"): "shipping",
	}, snapshot.ServiceByInstanceID)
}

func TestAzureInventoryConflictingIdentity(t *testing.T) {
	groups := []azureTestGroup{
		{name: "checkout", uuid: "vm-a", ips: []string{"10.0.0.1"}},
		{name: "payments", uuid: "VM-A", ips: []string{"10.0.0.2"}},
	}
	refresher := newAzureTestRefresher(t, azureInventoryHandler(t, &groups))
	snapshot := MetadataSnapshot{ServiceByIP: map[string]string{}, ServiceByInstanceID: map[string]string{}}
	require.ErrorContains(t, refresher.Refresh(t.Context(), &snapshot), "belongs to both")
	assert.Empty(t, snapshot.ServiceByIP)
	assert.Empty(t, snapshot.ServiceByInstanceID)
}

func TestAzureInventoryFlexibleNICFailure(t *testing.T) {
	const base = "/subscriptions/" + azureTestSubscription + "/resourceGroups/services/providers/Microsoft.Compute"
	const setID = base + "/virtualMachineScaleSets/checkout"
	const nicID = "/subscriptions/" + azureTestSubscription + "/resourceGroups/networking/providers/Microsoft.Network/networkInterfaces/checkout-nic"
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case base + "/virtualMachineScaleSets":
					_, _ = fmt.Fprintf(w, `{"value":[{"name":"checkout","id":%q,"properties":{"orchestrationMode":"Flexible"}}]}`, setID)
				case base + "/virtualMachines":
					_, _ = fmt.Fprintf(w, `{"value":[{"id":%q,"properties":{
						"vmId":"vm-a","virtualMachineScaleSet":{"id":%q},
						"instanceView":{"statuses":[{"code":"PowerState/running"}]},
						"networkProfile":{"networkInterfaces":[{"id":%q}]}
					}}]}`, base+"/virtualMachines/checkout-0", setID, nicID)
				case nicID:
					w.WriteHeader(status)
					_, _ = fmt.Fprint(w, `{"error":{"code":"TestError","message":"NIC unavailable"}}`)
				default:
					t.Errorf("unexpected SDK request: %s", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			snapshot := MetadataSnapshot{
				ServiceByIP:         map[string]string{"10.0.0.1": "checkout"},
				ServiceByInstanceID: map[string]string{AzureInstanceID(azureTestSubscription, "vm-a"): "checkout"},
			}
			require.ErrorContains(t, refresher.Refresh(t.Context(), &snapshot), "reading Azure network interface")
			assert.Equal(t, map[string]string{"10.0.0.1": "checkout"}, snapshot.ServiceByIP)
			assert.Equal(t, map[string]string{AzureInstanceID(azureTestSubscription, "vm-a"): "checkout"}, snapshot.ServiceByInstanceID)
		})
	}
}

func TestAzureInventoryRefreshDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		groups := []azureTestGroup{{name: "checkout", uuid: "vm-a"}}
		respond := azureInventoryHandler(t, &groups)
		calls := 0
		refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				time.Sleep(defaultAzureRefreshTimeout / 2)
				respond(w, r)
				return
			}
			<-r.Context().Done()
			assert.ErrorIs(t, r.Context().Err(), context.DeadlineExceeded)
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		inventory := NewInventory([]MetadataRefresher{refresher})
		start := time.Now()
		run, err := InventoryRefresherNode(inventory, time.Minute)(t.Context())
		require.NoError(t, err)
		require.NotNil(t, run)
		assert.Equal(t, defaultAzureRefreshTimeout, time.Since(start))
		assert.Equal(t, 2, calls)
		require.NoError(t, t.Context().Err(), "refresh deadline must not cancel its parent")
		_, ok := inventory.ServiceNameForInstanceID(AzureInstanceID(azureTestSubscription, "vm-a"))
		assert.False(t, ok)
	})
}
