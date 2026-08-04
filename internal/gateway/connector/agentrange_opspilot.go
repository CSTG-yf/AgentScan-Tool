// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"net/http"
)

// AgentRangeOpsPilotConnector is a lab-local connector for AgentRange's
// OpsPilot/Langflow integration. It deliberately performs no host-agent setup:
// the AgentRange services call /api/v1/inspect/* directly with their own
// X-DefenseClaw-Client header and connector="opspilot" payload field.
type AgentRangeOpsPilotConnector struct {
	gatewayToken string
	masterKey    string
}

func NewAgentRangeOpsPilotConnector() *AgentRangeOpsPilotConnector {
	return &AgentRangeOpsPilotConnector{}
}

func (c *AgentRangeOpsPilotConnector) Name() string { return "opspilot" }

func (c *AgentRangeOpsPilotConnector) Description() string {
	return "AgentRange OpsPilot local inspect API connector"
}

func (c *AgentRangeOpsPilotConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *AgentRangeOpsPilotConnector) SubprocessPolicy() SubprocessPolicy     { return SubprocessNone }

func (c *AgentRangeOpsPilotConnector) Setup(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	_ = opts
	return nil
}

func (c *AgentRangeOpsPilotConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	_ = opts
	return nil
}

func (c *AgentRangeOpsPilotConnector) VerifyClean(opts SetupOpts) error {
	_ = opts
	return nil
}

func (c *AgentRangeOpsPilotConnector) Authenticate(r *http.Request) bool {
	return authenticateHookBridgeRequest(r, c.gatewayToken, c.masterKey, c.Name(),
		"AgentRange OpsPilot uses local inspect API calls; loopback remains accepted for lab traffic", nil)
}

func (c *AgentRangeOpsPilotConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{
		RawBody:         body,
		RawModel:        ParseModelFromBody(body),
		Stream:          ParseStreamFromBody(body),
		PassthroughMode: !isChatPath(r.URL.Path),
		ConnectorName:   c.Name(),
	}, nil
}

func (c *AgentRangeOpsPilotConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *AgentRangeOpsPilotConnector) HookCapabilities(opts SetupOpts) HookCapability {
	_ = opts
	return HookCapability{
		CanBlock:           true,
		CanAskNative:       false,
		BlockEvents:        []string{"tool_call", "tool_result", "prompt", "response"},
		SupportsFailClosed: true,
		Scope:              "lab",
	}
}

func (c *AgentRangeOpsPilotConnector) HookProfile(opts SetupOpts) HookProfile {
	return HookProfile{
		Name:                c.Name(),
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: false,
		SupportedEvents:     []string{"tool_call", "tool_result", "prompt", "response"},
		AIDSurfaces:         []string{"tool_call", "tool_result", "prompt", "response"},
	}
}
