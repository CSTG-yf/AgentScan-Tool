package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestHookRuntimeEventCarriesMCPServerForEnforcement(t *testing.T) {
	store, _ := testStoreAndLogger(t)
	SetRuntimeEventStore(store)
	t.Cleanup(func() { SetRuntimeEventStore(nil) })
	api := &APIServer{store: store}
	api.recordHookRuntimeEvent(context.Background(), agentHookRequest{
		ConnectorName: "codex", HookEventName: "PreToolUse", ToolName: "mcp__jira__createIssue",
		Payload: map[string]interface{}{"mcp_server_name": "jira"},
	}, agentHookResponse{Action: "allow", Mode: "action"})
	rows, err := store.ListRuntimeEvents(audit.RuntimeEventFilter{EventSource: audit.RuntimeSourceAgentHook, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].MCPServer != "jira" || rows[0].Attributes["connector"] != "codex" {
		t.Fatalf("MCP hook evidence = %+v", rows)
	}
}
