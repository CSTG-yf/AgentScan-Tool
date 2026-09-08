package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// File rules share the desktop policy. Only synchronous, pre-read tool hooks
// can enforce this action; the Windows audit service remains observe-only.
type fileReadPolicy struct {
	Enabled   bool   `json:"enabled"`
	Mode      string `json:"mode"`
	FileGuard struct {
		Enabled   bool           `json:"enabled"`
		Blacklist []fileReadRule `json:"blacklist"`
	} `json:"fileGuard"`
}

type fileReadRule struct {
	ID        string   `json:"id"`
	Enabled   bool     `json:"enabled"`
	Path      string   `json:"path"`
	MatchKind string   `json:"matchKind"`
	Access    []string `json:"access"`
	Action    string   `json:"action"`
}

// Restrict shell support to one literal read with no pipeline, expansion,
// redirect, wrapper, or additional command. Never rewrite arbitrary scripts.
var literalReadCommand = regexp.MustCompile(`(?i)^\s*(cat|Get-Content)\s+(?:-LiteralPath\s+|-Path\s+)?(?:'([^'\r\n]+)'|"([^"$` + "`" + `\r\n]+)"|([^\s'"$` + "`" + `;&|<>()*?]+))\s*$`)

func fileReadTarget(tool string, input map[string]interface{}) (string, string, bool) {
	switch strings.ToLower(tool) {
	case "read", "read_file":
		for _, key := range []string{"file_path", "path"} {
			if path, ok := input[key].(string); ok && path != "" {
				return path, key, true
			}
		}
	case "bash", "shell", "shell_command", "exec_command":
		for _, key := range []string{"command", "cmd"} {
			command, ok := input[key].(string)
			if !ok {
				continue
			}
			m := literalReadCommand.FindStringSubmatch(command)
			if m == nil {
				continue
			}
			path := firstNonEmpty(m[2], m[3], m[4])
			// Wildcards and expansions are intentionally outside this adapter.
			if strings.ContainsAny(path, "*?$`\x00") {
				return "", "", false
			}
			return path, key, true
		}
	}
	return "", "", false
}

func canonicalReadPath(path, cwd string) (string, error) {
	if !filepath.IsAbs(path) {
		if !filepath.IsAbs(cwd) {
			return "", errors.New("file read requires an absolute working directory")
		}
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path, nil
}

func (p fileReadPolicy) match(path, cwd string) *fileReadRule {
	if !p.Enabled || !p.FileGuard.Enabled || p.Mode != "enforce" {
		return nil
	}
	target, err := canonicalReadPath(path, cwd)
	if err != nil {
		return nil
	}
	for i := range p.FileGuard.Blacklist {
		rule := &p.FileGuard.Blacklist[i]
		if !rule.Enabled || (rule.Action != "returnEmptyContent" && rule.Action != "terminateAgentTree") {
			continue
		}
		reads := false
		for _, access := range rule.Access {
			reads = reads || access == "read" || access == "any"
		}
		if !reads || !filepath.IsAbs(rule.Path) {
			continue
		}
		root, err := canonicalReadPath(rule.Path, cwd)
		if err != nil {
			continue
		}
		if (rule.MatchKind == "exact" && target == root) ||
			(rule.MatchKind == "subtree" && (target == root || strings.HasPrefix(target, strings.TrimRight(root, string(filepath.Separator))+string(filepath.Separator)))) {
			return rule
		}
	}
	return nil
}

func loadFileReadPolicy() (fileReadPolicy, error) {
	var policy fileReadPolicy
	path := os.Getenv("DEFENSECLAW_FILE_GUARD_POLICY")
	if path == "" {
		if runtime.GOOS != "windows" {
			return policy, nil
		}
		path = filepath.Join(os.Getenv("ProgramData"), "DefenseClaw", "process-guard.json")
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return policy, nil
	}
	if err != nil {
		return policy, fmt.Errorf("file guard policy is unreadable")
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		return policy, fmt.Errorf("file guard policy is invalid")
	}
	return policy, nil
}

// O_EXCL prevents truncating an existing file or following a preplanted link.
// An existing substitute is accepted only if it remains a regular empty file.
func emptyReadFile() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "TraceBastion", "file-read-guard")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "empty.txt")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		err = f.Close()
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		return "", errors.New("empty read substitute is not an empty regular file")
	}
	return path, nil
}

func codexCanRewriteRead(version string) bool {
	version = strings.TrimPrefix(strings.TrimSpace(version), "codex-cli ")
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) != 3 {
		return false
	}
	major, e1 := strconv.Atoi(parts[0])
	minor, e2 := strconv.Atoi(parts[1])
	patch, e3 := strconv.Atoi(parts[2])
	// Conservative verified floor: upstream rust-v0.153.4 includes updatedInput.
	return e1 == nil && e2 == nil && e3 == nil && (major > 0 || minor > 153 || (minor == 153 && patch >= 4))
}

func (a *APIServer) rewriteFileRead(name, event, mode, tool, cwd string, input map[string]interface{}) (map[string]interface{}, string, error) {
	if event != "PreToolUse" || mode != "action" {
		return nil, "", nil
	}
	target, key, supported := fileReadTarget(tool, input)
	if !supported {
		return nil, "", nil
	}
	policy, err := loadFileReadPolicy()
	if err != nil {
		return nil, "", err
	}
	if workdir, ok := input["workdir"].(string); ok && filepath.IsAbs(workdir) {
		cwd = workdir
	}
	rule := policy.match(target, cwd)
	if rule == nil {
		return nil, "", nil
	}
	if name == "codex" && !codexCanRewriteRead(connector.LoadCachedAgentVersion(a.configDataDir(), "codex")) {
		return nil, rule.ID, errors.New("empty file reads require Codex CLI 0.153.4 or newer; upgrade and rerun connector setup to refresh its version")
	}
	empty, err := emptyReadFile()
	if err != nil {
		return nil, rule.ID, errors.New("cannot prepare empty file substitute")
	}
	updated := make(map[string]interface{}, len(input))
	for k, v := range input {
		updated[k] = v
	}
	if key == "command" || key == "cmd" {
		if strings.ContainsAny(empty, "'\r\n") {
			return nil, rule.ID, errors.New("empty substitute path cannot be quoted safely")
		}
		original := literalReadCommand.FindStringSubmatch(input[key].(string))
		updated[key] = original[1] + " '" + filepath.ToSlash(empty) + "'"
	} else {
		updated[key] = empty
		delete(updated, "offset")
		delete(updated, "limit")
		delete(updated, "pages")
	}
	return updated, rule.ID, nil
}

func emptyReadHookOutput(updated map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
		"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": updated,
	}}
}

func (a *APIServer) auditEmptyRead(ctx context.Context, name, rule string) {
	if a.logger != nil {
		_ = a.logger.LogActionCtx(ctx, "file_read_empty", name, "rule="+rule+" action=returnEmptyContent outcome=rewriteIssued")
	}
}
