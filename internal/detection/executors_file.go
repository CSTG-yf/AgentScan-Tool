package detection

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

var fileReadDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FileBlockExecutor installs an exact-file, connector-scoped gate that the
// controlled Codex/Claude Code pre-read hook checks before a supported read.
// It cannot retroactively block the event that produced the detection or
// intercept arbitrary Linux read(2) calls outside the controlled path.
type FileBlockExecutor struct{ Store *audit.Store }

func (FileBlockExecutor) Point() string { return audit.EnforcementPointFile }

func (e FileBlockExecutor) Execute(ctx context.Context, req RuntimeExecutionRequest) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if e.Store == nil {
		return "", "", fmt.Errorf("file policy store unavailable")
	}
	if req.Decision.DetectionID == "" {
		return "", "", fmt.Errorf("file blacklist detection is required")
	}
	detection, _, err := e.Store.GetRuntimeDetectionDetail(req.Decision.DetectionID)
	if err != nil {
		return "", "", fmt.Errorf("load file detection: %w", err)
	}
	if detection.Attributes["blacklist_target_type"] != "path" {
		return "", "", fmt.Errorf("only an explicit path blacklist can justify a persistent file gate")
	}
	var digest, connector string
	for _, item := range req.Evidence {
		ev := item.Event
		if ev.EventSource != audit.RuntimeSourceAgentHook || ev.EventType != audit.RuntimeEventToolPreCall {
			continue
		}
		value, _ := ev.Attributes["file_read_path_sha256"].(string)
		scope, _ := ev.Attributes["connector"].(string)
		if !fileReadDigestPattern.MatchString(value) || (scope != "codex" && scope != "claudecode") {
			continue
		}
		if digest != "" && (digest != value || connector != scope) {
			return "", "", fmt.Errorf("ambiguous file evidence: multiple paths or connectors")
		}
		digest, connector = value, scope
	}
	if digest == "" {
		return "", "", fmt.Errorf("no controlled pre-read hook evidence with an exact file identity")
	}
	policy := enforce.NewPolicyEngine(e.Store)
	if err := policy.BlockForConnector("file_read_sha256", digest, connector, "runtime decision "+req.Decision.DecisionID); err != nil {
		return digest, "", err
	}
	blocked, err := policy.IsBlockedForConnector("file_read_sha256", digest, connector)
	if err != nil {
		return digest, "", fmt.Errorf("file gate verification failed: %w", err)
	}
	if !blocked {
		return digest, "", fmt.Errorf("file gate was not effective after writing policy")
	}
	return digest, "persistent " + strings.TrimSpace(connector) + " pre-read gate verified for future exact-file calls; prior reads and uncontrolled processes cannot be reversed", nil
}
