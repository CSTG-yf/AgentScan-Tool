//go:build linux

package detection

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLinuxProcessExecutorConfirmsExit(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	result, err := terminateProcessTrees(context.Background(), []uint32{uint32(cmd.Process.Pid)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "confirmed exit") {
		t.Fatalf("unverified success: %q", result)
	}
}

func TestLinuxProcessExecutorRefusesGatewayTree(t *testing.T) {
	_, err := terminateProcessTrees(context.Background(), []uint32{uint32(os.Getppid())})
	if err == nil || !strings.Contains(err.Error(), "containing the gateway") {
		t.Fatalf("expected self-protection, got %v", err)
	}
}
