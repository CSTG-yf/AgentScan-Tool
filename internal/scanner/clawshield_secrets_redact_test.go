// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

func TestRedactSecretsInContent(t *testing.T) {
	content := `# agent config
name: demo-skill
description: A helpful skill
api_key = "sk_live_abcdefghijklmnopqrstuvwx"
aws_access_key_id: AKIAIOSFODNN7EXAMPLE
github_token: ghp_abcdefghijklmnopqrstuvwxyz0123456789
slack_webhook_url: https://hooks.slack.com/services/T123/B456/xyzsecretvalue
password: SuperSecret123!
endpoint: https://api.example.com/v1
line_count: 42
`
	out, count := RedactSecretsInContent(content)

	if count == 0 {
		t.Fatalf("expected redactions, got 0; output:\n%s", out)
	}
	for _, secret := range []string{"sk_live_abcdefghijklmnopqrstuvwx", "AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "xyzsecretvalue", "SuperSecret123!"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q still present in output:\n%s", secret, out)
		}
	}
	for _, keep := range []string{"name: demo-skill", "endpoint: https://api.example.com/v1", "line_count: 42"} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-secret fragment %q missing from output:\n%s", keep, out)
		}
	}
	if !strings.Contains(out, "[REDACTED:") {
		t.Errorf("expected [REDACTED:<rule>] placeholders, got:\n%s", out)
	}
}

func TestRedactSecretsInContentPrefixedKeys(t *testing.T) {
	// Prefixed key names (github_api_key, anthropic-auth-token) and values
	// that no provider rule recognizes must still be redacted by the
	// generic key/token rules.
	content := "github_api_key = abcdefghijklmnopqrstuvwxyz012345\nanthropic-auth-token: sk-ant-unknown-format-value\n"
	out, count := RedactSecretsInContent(content)
	if count < 2 {
		t.Fatalf("expected >=2 redactions, got %d; output:\n%s", count, out)
	}
	if strings.Contains(out, "abcdefghijklmnopqrstuvwxyz012345") || strings.Contains(out, "sk-ant-unknown-format-value") {
		t.Fatalf("prefixed-key secret leaked:\n%s", out)
	}
}

func TestRedactSecretsInContentEnvFile(t *testing.T) {
	// Mirrors the AgentRange .env.example: generic secret key names and
	// short default passwords must be redacted too.
	content := "LANGFLOW_SUPERUSER=admin\nLANGFLOW_SUPERUSER_PASSWORD=admin\nJWT_SECRET=change-me-weak-secret\nJWT_TTL_SECONDS=3600\nOPSPILOT_PROPAGATION=service-account\nPOSTGRES_HOST=postgres-customer\nPOSTGRES_PORT=5432\n"
	out, count := RedactSecretsInContent(content)
	if strings.Contains(out, "PASSWORD=admin") || strings.Contains(out, "change-me-weak-secret") {
		t.Fatalf("env-file secret leaked (count=%d):\n%s", count, out)
	}
	for _, keep := range []string{"LANGFLOW_SUPERUSER=admin", "JWT_TTL_SECONDS=3600", "POSTGRES_HOST=postgres-customer", "POSTGRES_PORT=5432"} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-secret fragment %q missing from output:\n%s", keep, out)
		}
	}
}

func TestRedactSecretsInContentPEM(t *testing.T) {
	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0123456789abcdefghijklmnopqrstuvwxyz\n-----END RSA PRIVATE KEY-----\nafter: ok\n"
	out, count := RedactSecretsInContent(content)
	if count == 0 || strings.Contains(out, "MIIEpA") || !strings.Contains(out, "after: ok") {
		t.Fatalf("PEM block not fully redacted (count=%d):\n%s", count, out)
	}
}

func TestRedactSecretsInContentNoSecrets(t *testing.T) {
	content := "hello world\nnothing sensitive here\n"
	out, count := RedactSecretsInContent(content)
	if count != 0 || out != content {
		t.Fatalf("expected no redactions, got count=%d output=%q", count, out)
	}
}
