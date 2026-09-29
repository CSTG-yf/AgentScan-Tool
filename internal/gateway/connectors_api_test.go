package gateway

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestConnectorsAPIExposesCapabilityAndHookContractProfiles(t *testing.T) {
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(connector.NewCodexConnector())
	api := &APIServer{
		connectorRegistry: registry,
		scannerCfg:        &config.Config{Guardrail: config.GuardrailConfig{Connector: "codex"}},
	}
	recorder := httptest.NewRecorder()
	api.handleConnectors(recorder, httptest.NewRequest("GET", "/v1/connectors", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Active     string `json:"active"`
		Connectors []struct {
			Name             string `json:"name"`
			HookCapabilities struct {
				CanBlock bool `json:"can_block"`
			} `json:"hook_capabilities"`
			HookContracts []struct {
				ID              string   `json:"id"`
				MinAgentVersion string   `json:"min_agent_version"`
				Events          []string `json:"events"`
			} `json:"hook_contracts"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode connector response: %v", err)
	}
	if response.Active != "codex" || len(response.Connectors) != 1 {
		t.Fatalf("active/connectors = %q/%d, want codex/1", response.Active, len(response.Connectors))
	}
	entry := response.Connectors[0]
	if entry.Name != "codex" || !entry.HookCapabilities.CanBlock {
		t.Fatalf("capability profile missing: %+v", entry)
	}
	if len(entry.HookContracts) == 0 || entry.HookContracts[0].ID == "" || len(entry.HookContracts[0].Events) == 0 {
		t.Fatalf("versioned hook contracts missing: %+v", entry.HookContracts)
	}
}
