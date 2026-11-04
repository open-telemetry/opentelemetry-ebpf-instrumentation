// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureFlexibleNIC(t *testing.T) {
	const prefix = "/subscriptions/" + azureTestSubscription
	const nicID = prefix + "/resourceGroups/networking/providers/Microsoft.Network/networkInterfaces/checkout"
	for _, tc := range []struct {
		name      string
		id        string
		wantError string
	}{
		{name: "another resource group", id: nicID},
		{name: "case insensitive", id: strings.ToUpper(nicID)},
		{name: "malformed", id: "not-an-arm-id", wantError: "parsing Azure network interface reference"},
		{name: "other subscription", id: strings.Replace(nicID, azureTestSubscription, "other", 1), wantError: "invalid Azure network interface reference"},
		{name: "wrong type", id: prefix + "/resourceGroups/networking/providers/Microsoft.Compute/virtualMachines/checkout", wantError: "invalid Azure network interface reference"},
		{name: "missing resource group", id: prefix + "/providers/Microsoft.Network/networkInterfaces/checkout", wantError: "invalid Azure network interface reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, http.MethodGet, r.Method)
				assert.True(t, strings.EqualFold(nicID, r.URL.Path))
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"name":"checkout","properties":{}}`)
			})
			nic, err := refresher.flexibleNIC(t.Context(), tc.id)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				assert.Zero(t, calls, "invalid references must not issue an API request")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, nic.Name)
			assert.Equal(t, "checkout", *nic.Name)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestAzureFlexibleVMs(t *testing.T) {
	const base = "/subscriptions/" + azureTestSubscription + "/resourceGroups/services/providers/Microsoft.Compute"
	const setID = base + "/virtualMachineScaleSets/checkout"
	const vmID = base + "/virtualMachines/checkout-0"
	const nicID = "/subscriptions/" + azureTestSubscription + "/resourceGroups/networking/providers/Microsoft.Network/networkInterfaces/checkout"
	running := fmt.Sprintf(`{"id":%q,"properties":{
		"vmId":"vm-a","virtualMachineScaleSet":{"id":%q},
		"instanceView":{"statuses":[{"code":"PowerState/running"}]},
		"networkProfile":{"networkInterfaces":[{"id":%q},{"id":%q}]}
	}}`, vmID, strings.ToUpper(setID), nicID, nicID+"-secondary")
	nic := fmt.Sprintf(`{"properties":{"virtualMachine":{"id":%q},"ipConfigurations":[
		{"properties":{"privateIPAddress":"::ffff:10.0.0.1"}},
		{"properties":{"privateIPAddress":"2001:0db8::1"}}
	]}}`, strings.ToUpper(vmID))
	for _, tc := range []struct {
		name      string
		pages     []string
		nic       string
		failLast  bool
		wantError string
		wantVMs   int
		wantNICs  int
		wantIPs   []string
	}{
		{
			name: "multiple NICs and addresses", pages: []string{running}, nic: nic, wantVMs: 1, wantNICs: 2,
			wantIPs: []string{"10.0.0.1", "2001:db8::1", "10.0.0.2"},
		},
		{
			name: "pagination and stopped VMs", pages: []string{strings.ReplaceAll(running, "PowerState/running", "PowerState/deallocated"), running},
			nic: nic, wantVMs: 1, wantNICs: 2, wantIPs: []string{"10.0.0.1", "2001:db8::1", "10.0.0.2"},
		},
		{name: "unknown power state", pages: []string{strings.ReplaceAll(running, "PowerState/running", "ProvisioningState/succeeded")}},
		{name: "empty", pages: []string{""}},
		{name: "later page denied", pages: []string{running, ""}, nic: nic, failLast: true, wantNICs: 2, wantError: "listing Azure flexible scale set"},
		{name: "missing properties", pages: []string{`{}`}, wantError: "VM without properties"},
		{name: "null VM", pages: []string{`null`}, wantError: "VM without properties"},
		{name: "wrong membership", pages: []string{strings.ReplaceAll(running, strings.ToUpper(setID), setID+"-other")}, wantError: "unexpected scale set membership"},
		{name: "missing UUID", pages: []string{strings.ReplaceAll(running, `"vmId":"vm-a"`, `"vmId":""`)}, wantError: "no resource ID or UUID"},
		{name: "missing resource ID", pages: []string{strings.ReplaceAll(running, vmID, "")}, wantError: "no resource ID or UUID"},
		{name: "empty NIC reference", pages: []string{strings.ReplaceAll(running, nicID, "")}, wantError: "network interface without an ID"},
		{name: "NIC without properties", pages: []string{running}, nic: `{}`, wantNICs: 1, wantError: "has no properties"},
		{name: "invalid IP", pages: []string{running}, nic: strings.ReplaceAll(nic, "::ffff:10.0.0.1", "invalid"), wantNICs: 1, wantError: "invalid Azure private IP"},
		{
			name: "reassigned NIC", pages: []string{running}, nic: strings.ReplaceAll(nic, strings.ToUpper(vmID), vmID+"-other"),
			wantVMs: 1, wantNICs: 2, wantIPs: []string{"10.0.0.2"},
		},
		{
			name: "detached NIC", pages: []string{running}, nic: `{"properties":{}}`,
			wantVMs: 1, wantNICs: 2, wantIPs: []string{"10.0.0.2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pages, nics := 0, 0
			refresher := newAzureTestRefresher(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case base + "/virtualMachines":
					if !assert.Less(t, pages, len(tc.pages)) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if pages == 0 {
						assert.Equal(t, "'virtualMachineScaleSet/id' eq '"+setID+"'", r.URL.Query().Get("$filter"))
						assert.Equal(t, "instanceView", r.URL.Query().Get("$expand"))
					} else {
						assert.Equal(t, "next", r.URL.Query().Get("$skiptoken"))
					}
					page := tc.pages[pages]
					pages++
					if tc.failLast && pages == len(tc.pages) {
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, `{"error":{"code":"AuthorizationFailed","message":"denied"}}`)
						return
					}
					if pages < len(tc.pages) {
						_, _ = fmt.Fprintf(w, `{"value":[%s],"nextLink":%q}`, page,
							"https://management.azure.com"+base+"/virtualMachines?api-version=2026-04-01&$skiptoken=next")
					} else {
						_, _ = fmt.Fprintf(w, `{"value":[%s]}`, page)
					}
				case nicID:
					nics++
					_, _ = fmt.Fprint(w, tc.nic)
				case nicID + "-secondary":
					nics++
					_, _ = fmt.Fprintf(w, `{"properties":{"virtualMachine":{"id":%q},"ipConfigurations":[{"properties":{"privateIPAddress":"10.0.0.2"}}]}}`, vmID)
				default:
					t.Errorf("unexpected SDK request: %s", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			vms, err := refresher.flexibleVMs(t.Context(), setID)
			assert.Equal(t, tc.wantNICs, nics)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				assert.Nil(t, vms, "failed discovery must not return partial results")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, len(tc.pages), pages)
			require.Len(t, vms, tc.wantVMs)
			if tc.wantVMs > 0 {
				assert.Equal(t, "vm-a", vms[0].uuid)
				assert.ElementsMatch(t, tc.wantIPs, vms[0].privateIPs)
			}
		})
	}
}
