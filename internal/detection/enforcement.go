// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// NetworkBlocklist is the runtime-enforced egress deny list. When the
// policy engine emits a BLOCK decision with the proxy enforcement
// point (action mode), the destination hosts from the detection's
// evidence land here and the proxy returns 403 for them — the
// Detection → Decision → Response loop this project needs, without
// touching the existing proxy policy code paths.
//
// Entries expire (default 1h) so a false positive self-heals instead
// of bricking the machine, and the list persists in app_settings so a
// sidecar restart keeps enforcing.
type NetworkBlocklist struct {
	mu            sync.RWMutex
	entries       map[string]blocklistEntry
	ttl           time.Duration
	persistTarget *audit.Store
}

type blocklistEntry struct {
	Host       string    `json:"host"`
	DecisionID string    `json:"decision_id"`
	AddedAt    time.Time `json:"added_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// runtimeNetworkBlocklistSettingKey persists the blocklist JSON.
const runtimeNetworkBlocklistSettingKey = "runtime_network_blocklist"

// defaultBlocklistTTL bounds how long one BLOCK decision keeps a host
// denied. Operators can clear it via the decisions API afterwards.
const defaultBlocklistTTL = time.Hour

// NewNetworkBlocklist builds an empty in-memory blocklist.
func NewNetworkBlocklist() *NetworkBlocklist {
	return &NetworkBlocklist{
		entries: map[string]blocklistEntry{},
		ttl:     defaultBlocklistTTL,
	}
}

// AddHosts denies the given hosts on behalf of one decision and
// persists the list. Already-blocked hosts are skipped; the returned
// slice lists the hosts newly denied by THIS call.
func (b *NetworkBlocklist) AddHosts(hosts []string, decisionID string) []string {
	if b == nil || len(hosts) == 0 {
		return nil
	}
	now := time.Now().UTC()
	b.mu.Lock()
	var added []string
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if e, ok := b.entries[host]; ok && e.ExpiresAt.After(now) {
			continue
		}
		b.entries[host] = blocklistEntry{
			Host: host, DecisionID: decisionID,
			AddedAt: now, ExpiresAt: now.Add(b.ttl),
		}
		added = append(added, host)
	}
	snapshot := b.snapshotLocked()
	b.mu.Unlock()

	if len(added) > 0 {
		b.persist(snapshot)
	}
	return added
}

// IsBlocked reports whether a host is currently denied, plus the
// decision that denied it (for the 403 body and audit event).
func (b *NetworkBlocklist) IsBlocked(host string) (bool, string) {
	if b == nil {
		return false, ""
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false, ""
	}
	now := time.Now().UTC()
	b.mu.RLock()
	defer b.mu.RUnlock()
	e, ok := b.entries[host]
	if !ok {
		return false, ""
	}
	if !e.ExpiresAt.After(now) {
		return false, ""
	}
	return true, e.DecisionID
}

// Entries returns the live entries (unexpired), oldest first.
func (b *NetworkBlocklist) Entries() []blocklistEntry {
	if b == nil {
		return nil
	}
	now := time.Now().UTC()
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []blocklistEntry
	for _, e := range b.entries {
		if e.ExpiresAt.After(now) {
			out = append(out, e)
		}
	}
	// Deterministic order for display.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].AddedAt.Before(out[j-1].AddedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Remove clears one host (operator unblock).
func (b *NetworkBlocklist) Remove(host string) {
	if b == nil {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	b.mu.Lock()
	delete(b.entries, host)
	snapshot := b.snapshotLocked()
	b.mu.Unlock()
	b.persist(snapshot)
}

// snapshotLocked copies live entries; caller holds the lock.
func (b *NetworkBlocklist) snapshotLocked() []blocklistEntry {
	now := time.Now().UTC()
	out := make([]blocklistEntry, 0, len(b.entries))
	for _, e := range b.entries {
		if e.ExpiresAt.After(now) {
			out = append(out, e)
		}
	}
	return out
}

// persist writes the snapshot to app_settings so enforcement survives
// restarts. Best-effort: a persistence failure never blocks denying.
func (b *NetworkBlocklist) persist(entries []blocklistEntry) {
	if b.persistTarget == nil {
		return
	}
	_ = b.persistTarget.SaveJSONSetting(runtimeNetworkBlocklistSettingKey, entries)
}

// persistTarget is set by the policy engine (the audit store). Kept
// unexported so the blocklist stays a plain data structure in tests.
func (b *NetworkBlocklist) setPersistTarget(s *audit.Store) {
	b.persistTarget = s
	b.reload(s)
}

// reload loads persisted entries younger than their expiry.
func (b *NetworkBlocklist) reload(s *audit.Store) {
	if s == nil {
		return
	}
	var entries []blocklistEntry
	if _, err := s.LoadJSONSetting(runtimeNetworkBlocklistSettingKey, &entries); err != nil || len(entries) == 0 {
		return
	}
	now := time.Now().UTC()
	b.mu.Lock()
	for _, e := range entries {
		if e.Host != "" && e.ExpiresAt.After(now) {
			b.entries[strings.ToLower(e.Host)] = e
		}
	}
	b.mu.Unlock()
}

// blocklistBlockedResponse is the 403 body shape the proxy writes when
// the runtime policy engine denies a host.
type blocklistBlockedResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// WriteBlockedResponse emits the runtime-decision 403. Kept here so
// the proxy call site stays a one-liner.
func WriteBlockedResponse(w http.ResponseWriter, host, decisionID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	body := blocklistBlockedResponse{
		Error:  "request blocked by runtime security decision",
		Detail: "host " + host + " denied by decision " + decisionID,
	}
	_ = json.NewEncoder(w).Encode(body)
}
