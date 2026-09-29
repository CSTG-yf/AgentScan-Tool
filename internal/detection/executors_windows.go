//go:build windows

package detection

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procattr"
)

func terminateProcessTrees(ctx context.Context, pids []uint32) (string, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, pid := range pids {
		cmd := exec.CommandContext(deadlineCtx, "taskkill.exe", "/PID", strconv.FormatUint(uint64(pid), 10), "/T", "/F")
		procattr.Apply(cmd)
		if output, err := cmd.CombinedOutput(); err != nil {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = err.Error()
			}
			return "", fmt.Errorf("taskkill PID %d failed: %s", pid, message)
		}
	}
	return "terminated process tree(s) via taskkill", nil
}
