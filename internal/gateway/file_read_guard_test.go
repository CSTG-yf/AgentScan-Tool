package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestFileReadGuardHTTPChain(t *testing.T) {
	a, secret := setupFileReadGuard(t)
	for _, name := range []string{"claudecode", "codex"} {
		payload, _ := json.Marshal(map[string]interface{}{
			"hook_event_name": "PreToolUse", "tool_name": "Read",
			"tool_input": map[string]interface{}{"file_path": secret}, "cwd": filepath.Dir(secret),
		})
		recorder := httptest.NewRecorder()
		a.handleUnifiedConnectorHook(name)(recorder, httptest.NewRequest("POST", "/hook", bytes.NewReader(payload)))
		var response map[string]interface{}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		field := "codex_output"
		if name == "claudecode" {
			field = "claude_code_output"
		}
		output, ok := response[field].(map[string]interface{})
		if recorder.Code != 200 || response["action"] != "allow" || !ok {
			t.Fatalf("%s: %s", name, recorder.Body.String())
		}
		specific := output["hookSpecificOutput"].(map[string]interface{})
		updated := specific["updatedInput"].(map[string]interface{})
		data, err := os.ReadFile(updated["file_path"].(string))
		if err != nil || len(data) != 0 {
			t.Fatalf("%s: data=%q err=%v", name, data, err)
		}
	}
}

func setupFileReadGuard(t *testing.T) (*APIServer, string) {
	t.Helper()
	dir := t.TempDir()
	// Isolate the substitute file from the real user's cache.
	t.Setenv("LOCALAPPDATA", dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	secret := filepath.Join(dir, "sensitive file.txt")
	if err := os.WriteFile(secret, []byte("secret must never reach the tool result"), 0600); err != nil {
		t.Fatal(err)
	}
	p := fileReadPolicy{Enabled: true, Mode: "enforce"}
	p.FileGuard.Enabled = true
	p.FileGuard.Blacklist = []fileReadRule{{ID: "file.test", Enabled: true, Path: secret, MatchKind: "exact", Access: []string{"read"}, Action: "returnEmptyContent"}}
	data, _ := json.Marshal(p)
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_FILE_GUARD_POLICY", policyPath)
	if err := os.WriteFile(filepath.Join(dir, "agent_discovery.json"), []byte(`{"agents":{"codex":{"version":"0.153.4"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: dir}
	cfg.Guardrail.Mode = "action"
	cfg.Codex.Enabled = true
	cfg.ClaudeCode.Enabled = true
	return &APIServer{scannerCfg: cfg}, secret
}

func TestFileReadGuardConnectorOutputs(t *testing.T) {
	a, secret := setupFileReadGuard(t)
	for _, name := range []string{"claudecode", "codex"} {
		t.Run(name, func(t *testing.T) {
			input := map[string]interface{}{"file_path": secret, "offset": 100, "limit": 20}
			var output map[string]interface{}
			var action string
			if name == "codex" {
				r := a.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: input, CWD: filepath.Dir(secret)})
				output, action = r.CodexOutput, r.Action
			} else {
				r := a.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: input, CWD: filepath.Dir(secret)})
				output, action = r.ClaudeCodeOutput, r.Action
			}
			if action != "allow" {
				t.Fatalf("action=%s output=%v", action, output)
			}
			specific, ok := output["hookSpecificOutput"].(map[string]interface{})
			if !ok || specific["permissionDecision"] != "allow" {
				t.Fatalf("output=%v", output)
			}
			updated := specific["updatedInput"].(map[string]interface{})
			content, err := os.ReadFile(updated["file_path"].(string))
			if err != nil || len(content) != 0 {
				t.Fatalf("substitute content=%q err=%v", content, err)
			}
			if _, ok := updated["offset"]; ok {
				t.Fatal("offset would break empty reads")
			}
			original, _ := os.ReadFile(secret)
			if len(original) == 0 || input["file_path"] != secret {
				t.Fatal("original file/input changed")
			}
		})
	}
}

func TestFileReadGuardShellReturnsZeroBytes(t *testing.T) {
	a, secret := setupFileReadGuard(t)
	command, shell, flag := "cat '"+filepath.ToSlash(secret)+"'", "sh", "-c"
	if runtime.GOOS == "windows" {
		command, shell, flag = "Get-Content -LiteralPath '"+secret+"'", "powershell.exe", "-Command"
	}
	updated, _, err := a.rewriteFileRead("codex", "PreToolUse", "action", "Bash", filepath.Dir(secret), map[string]interface{}{"command": command})
	if err != nil || updated == nil {
		t.Fatalf("updated=%v err=%v", updated, err)
	}
	output, err := exec.Command(shell, flag, updated["command"].(string)).CombinedOutput()
	if err != nil || len(output) != 0 {
		t.Fatalf("output=%q err=%v", output, err)
	}
}

func TestFileReadGuardBoundaries(t *testing.T) {
	a, secret := setupFileReadGuard(t)
	for _, test := range []struct {
		event, mode, tool string
		input             map[string]interface{}
	}{
		{"PostToolUse", "action", "Read", map[string]interface{}{"file_path": secret}},
		{"PreToolUse", "observe", "Read", map[string]interface{}{"file_path": secret}},
		{"PreToolUse", "action", "Write", map[string]interface{}{"file_path": secret}},
		{"PreToolUse", "action", "Read", map[string]interface{}{"file_path": secret + ".public"}},
		{"PreToolUse", "action", "Bash", map[string]interface{}{"command": "cat '" + secret + "'; echo next"}},
		{"PreToolUse", "action", "Bash", map[string]interface{}{"command": "cat $SECRET"}},
	} {
		updated, _, err := a.rewriteFileRead("claudecode", test.event, test.mode, test.tool, filepath.Dir(secret), test.input)
		if err != nil || updated != nil {
			t.Fatalf("unexpected rewrite: %+v %v %v", test, updated, err)
		}
	}
	p, _ := loadFileReadPolicy()
	p.FileGuard.Blacklist[0].MatchKind = "subtree"
	p.FileGuard.Blacklist[0].Path = filepath.Join(filepath.Dir(secret), "private")
	if p.match(filepath.Join(filepath.Dir(secret), "private-other", "file"), filepath.Dir(secret)) != nil {
		t.Fatal("subtree crossed directory boundary")
	}
	if p.match(filepath.Join(filepath.Dir(secret), "private", "file"), filepath.Dir(secret)) == nil {
		t.Fatal("subtree child missed")
	}
	p.Mode = "observe"
	if p.match(secret, filepath.Dir(secret)) != nil {
		t.Fatal("observe enforced")
	}
}

func TestFileReadGuardOldCodexFailsWithoutReading(t *testing.T) {
	a, secret := setupFileReadGuard(t)
	if err := os.WriteFile(filepath.Join(a.configDataDir(), "agent_discovery.json"), []byte(`{"agents":{"codex":{"version":"0.120.0"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	r := a.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]interface{}{"file_path": secret}, CWD: filepath.Dir(secret)})
	if r.Action != "block" || !strings.Contains(r.Reason, "0.153.4") {
		t.Fatalf("response=%+v", r)
	}
}

func TestFileReadGuardRejectsNonemptySubstitute(t *testing.T) {
	_, _ = setupFileReadGuard(t)
	path, err := emptyReadFile()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unexpected content"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := emptyReadFile(); err == nil {
		t.Fatal("nonempty substitute accepted")
	}
}
