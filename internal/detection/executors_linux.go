//go:build linux

package detection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type processSnapshot struct {
	pid   int
	ppid  int
	start string
}

// terminateProcessTrees uses pidfds so a recycled numeric PID cannot receive
// the signal. It confirms that every process in the observed tree has exited;
// an inaccessible process or an unsupported kernel is a failure, not success.
func terminateProcessTrees(ctx context.Context, roots []uint32) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	processes, err := snapshotProcesses()
	if err != nil {
		return "", err
	}
	selected := map[int]int{}
	for _, root := range roots {
		if _, ok := processes[int(root)]; !ok {
			return "", fmt.Errorf("observed PID %d no longer exists", root)
		}
		selected[int(root)] = 0
	}
	for changed := true; changed; {
		changed = false
		for pid, proc := range processes {
			if depth, ok := selected[proc.ppid]; ok {
				if _, seen := selected[pid]; !seen {
					selected[pid] = depth + 1
					changed = true
				}
			}
		}
	}
	if _, ownProcess := selected[os.Getpid()]; ownProcess {
		return "", fmt.Errorf("refusing to contain a process tree containing the gateway")
	}
	type heldProcess struct {
		pid   int
		depth int
		fd    int
	}
	held := make([]heldProcess, 0, len(selected))
	defer func() {
		for _, proc := range held {
			_ = unix.Close(proc.fd)
		}
	}()
	for pid, depth := range selected {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			return "", fmt.Errorf("pidfd_open PID %d: %w", pid, err)
		}
		held = append(held, heldProcess{pid: pid, depth: depth, fd: fd})
		current, err := readProcessStat(pid)
		if err != nil || current.start != processes[pid].start {
			return "", fmt.Errorf("PID %d changed during containment; refusing a recycled target", pid)
		}
	}
	// Capture descendants before signaling the roots, because killing a parent
	// reparents its children and loses the original /proc parent relationship.
	sort.Slice(held, func(i, j int) bool { return held[i].depth < held[j].depth })
	for _, proc := range held {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := unix.PidfdSendSignal(proc.fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return "", fmt.Errorf("kill PID %d: %w", proc.pid, err)
		}
	}
	for _, proc := range held {
		for {
			if err := ctx.Err(); err != nil {
				return "", fmt.Errorf("PID %d exit not confirmed: %w", proc.pid, err)
			}
			pollFD := []unix.PollFd{{Fd: int32(proc.fd), Events: unix.POLLIN}}
			n, err := unix.Poll(pollFD, 50)
			if err != nil && !errors.Is(err, unix.EINTR) {
				return "", fmt.Errorf("confirm PID %d exit: %w", proc.pid, err)
			}
			if n > 0 && pollFD[0].Revents&unix.POLLIN != 0 {
				break
			}
		}
	}
	return fmt.Sprintf("confirmed exit of %d process(es) via pidfd", len(held)), nil
}

func snapshotProcesses() (map[int]processSnapshot, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	processes := make(map[int]processSnapshot, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if proc, err := readProcessStat(pid); err == nil {
			processes[pid] = proc
		}
	}
	return processes, nil
}

func readProcessStat(pid int) (processSnapshot, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return processSnapshot{}, err
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return processSnapshot{}, fmt.Errorf("invalid /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[closing+1:]))
	if len(fields) < 20 {
		return processSnapshot{}, fmt.Errorf("short /proc/%d/stat", pid)
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return processSnapshot{}, err
	}
	return processSnapshot{pid: pid, ppid: ppid, start: fields[19]}, nil
}
