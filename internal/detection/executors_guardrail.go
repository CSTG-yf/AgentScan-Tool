package detection

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GuardrailBlockExecutor reconciles an inline proxy block with the unified
// response record. It cannot initiate a retrospective prompt block: the
// proxy must already have selected its no-upstream branch before emitting
// the detection event.
type GuardrailBlockExecutor struct{ Store *audit.Store }

func (GuardrailBlockExecutor) Point() string { return audit.EnforcementPointGuardrail }

func (e GuardrailBlockExecutor) Execute(ctx context.Context, req RuntimeExecutionRequest) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if e.Store == nil || req.Decision.DetectionID == "" {
		return "", "", fmt.Errorf("guardrail detection store is unavailable")
	}
	detection, _, err := e.Store.GetRuntimeDetectionDetail(req.Decision.DetectionID)
	if err != nil {
		return "", "", fmt.Errorf("load guardrail detection: %w", err)
	}
	if detection.DetectionType != "prompt_injection" {
		return "", "", fmt.Errorf("guardrail receipt only supports prompt-injection detections")
	}
	for _, item := range req.Evidence {
		ev := item.Event
		if ev.EventSource != audit.RuntimeSourceGuardrail ||
			ev.Outcome != "blocked" ||
			ev.Attributes["direction"] != "prompt" ||
			ev.Attributes["proxy_pre_upstream_blocked"] != true {
			continue
		}
		target := strings.TrimSpace(ev.TraceID)
		if target == "" {
			target = strings.TrimSpace(ev.SessionID)
		}
		if target == "" {
			target = "proxy-prompt"
		}
		return target, "synchronous guardrail proxy selected the no-upstream block branch before this detection", nil
	}
	return "", "", fmt.Errorf("no confirmed synchronous proxy prompt-block receipt in detection evidence")
}
