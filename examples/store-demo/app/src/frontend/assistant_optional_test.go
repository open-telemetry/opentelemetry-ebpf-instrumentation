// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShoppingAssistantAddressIsOptional(t *testing.T) {
	t.Setenv("SHOPPING_ASSISTANT_SERVICE_ADDR", "")

	var addr string
	mapOptionalEnv(&addr, "SHOPPING_ASSISTANT_SERVICE_ADDR")

	if addr != "" {
		t.Fatalf("optional shopping assistant address = %q, want empty", addr)
	}
}

func TestAssistantEnabledRequiresConfiguredAddress(t *testing.T) {
	tests := []struct {
		name    string
		enabled string
		addr    string
		want    bool
	}{
		{
			name:    "disabled without address",
			enabled: "true",
			want:    false,
		},
		{
			name:    "disabled when flag is false",
			enabled: "false",
			addr:    "shoppingassistant:8080",
			want:    false,
		},
		{
			name:    "enabled with flag and address",
			enabled: "true",
			addr:    "shoppingassistant:8080",
			want:    true,
		},
		{
			name:    "enabled flag is case insensitive",
			enabled: "TRUE",
			addr:    "shoppingassistant:8080",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAssistantEnabled(tt.enabled, tt.addr); got != tt.want {
				t.Fatalf("isAssistantEnabled(%q, %q) = %v, want %v", tt.enabled, tt.addr, got, tt.want)
			}
		})
	}
}

func TestAssistantRoutesUnavailableWithoutAddress(t *testing.T) {
	oldAssistantEnabled := assistantEnabled
	assistantEnabled = true
	t.Cleanup(func() {
		assistantEnabled = oldAssistantEnabled
	})

	fe := &frontendServer{}

	assistantReq := httptest.NewRequest(http.MethodGet, "/assistant", nil)
	assistantResp := httptest.NewRecorder()
	fe.assistantHandler(assistantResp, assistantReq)

	if assistantResp.Code != http.StatusNotFound {
		t.Fatalf("assistant handler status = %d, want %d", assistantResp.Code, http.StatusNotFound)
	}

	botReq := httptest.NewRequest(http.MethodPost, "/bot", strings.NewReader(`{"message":"hello"}`))
	botResp := httptest.NewRecorder()
	fe.chatBotHandler(botResp, botReq)

	if botResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("bot handler status = %d, want %d", botResp.Code, http.StatusServiceUnavailable)
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(botResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode bot response: %v", err)
	}
	if body.Message == "" {
		t.Fatal("bot response message is empty")
	}
}
