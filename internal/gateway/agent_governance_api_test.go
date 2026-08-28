// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func newAgentGovernanceAPITest(t *testing.T) *APIServer {
	t.Helper()

	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return &APIServer{store: store, logger: audit.NewLogger(store)}
}

func agentGovernanceRequest(t *testing.T, api *APIServer, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleAgentGovernanceAPI(rec, req)
	return rec
}

func TestAgentGovernanceAgentTypeCRUD(t *testing.T) {
	api := newAgentGovernanceAPITest(t)

	createRec := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/agent-types", map[string]any{
		"type_key":    "test-agent-type",
		"name":        "Test Agent Type",
		"vendor":      "Test Vendor",
		"kind":        "cli",
		"runtime":     "go",
		"description": "created by gateway test",
		"enabled":     true,
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRec.Code, createRec.Body.String())
	}
	var created audit.GovernanceAgentTypeRow
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == 0 || created.TypeKey != "test-agent-type" || !created.Enabled {
		t.Fatalf("created row = %+v", created)
	}

	listRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/agent-types?keyword=test-agent-type", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listRec.Code, listRec.Body.String())
	}
	var page audit.GovernanceAgentTypePage
	if err := json.NewDecoder(listRec.Body).Decode(&page); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != created.ID {
		t.Fatalf("list page = %+v, want created row", page)
	}

	idPath := strconv.FormatInt(created.ID, 10)
	updateRec := agentGovernanceRequest(t, api, http.MethodPatch, "/api/v1/agent-governance/agent-types/"+idPath, map[string]any{
		"name":    "Updated Test Agent Type",
		"runtime": "node",
	})
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d body = %s", updateRec.Code, updateRec.Body.String())
	}
	var updated audit.GovernanceAgentTypeRow
	if err := json.NewDecoder(updateRec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Name != "Updated Test Agent Type" || updated.Runtime != "node" {
		t.Fatalf("updated row = %+v", updated)
	}

	deleteRec := agentGovernanceRequest(t, api, http.MethodDelete, "/api/v1/agent-governance/agent-types/"+idPath, nil)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d body = %s", deleteRec.Code, deleteRec.Body.String())
	}
	var disabled audit.GovernanceAgentTypeRow
	if err := json.NewDecoder(deleteRec.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !disabled.Deleted {
		t.Fatalf("delete should mark row deleted, got %+v", disabled)
	}

	listAfterDeleteRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/agent-types?keyword=test-agent-type", nil)
	if listAfterDeleteRec.Code != http.StatusOK {
		t.Fatalf("list after delete status = %d body = %s", listAfterDeleteRec.Code, listAfterDeleteRec.Body.String())
	}
	var afterDelete audit.GovernanceAgentTypePage
	if err := json.NewDecoder(listAfterDeleteRec.Body).Decode(&afterDelete); err != nil {
		t.Fatalf("decode list after delete response: %v", err)
	}
	if afterDelete.Total != 0 || len(afterDelete.Items) != 0 {
		t.Fatalf("deleted row should be hidden from list, got %+v", afterDelete)
	}
}

func TestAgentGovernanceReadEndpointsSmoke(t *testing.T) {
	api := newAgentGovernanceAPITest(t)

	for _, path := range []string{
		"/api/v1/agent-governance",
		"/api/v1/agent-governance/agent-types",
		"/api/v1/agent-governance/discovery-rules",
		"/api/v1/agent-governance/resource-rules",
		"/api/v1/agent-governance/scan-profiles",
		"/api/v1/agent-governance/scan-capabilities",
		"/api/v1/agent-governance/resource-actions",
		"/api/v1/agent-governance/admission-matrix",
		"/api/v1/agent-governance/risk-model",
	} {
		t.Run(path, func(t *testing.T) {
			rec := agentGovernanceRequest(t, api, http.MethodGet, path, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}
