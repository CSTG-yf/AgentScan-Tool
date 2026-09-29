// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "time"

const (
	agentrangeRuntimeCacheTTL     = 30 * time.Second
	agentrangeRuntimeSessionLimit = 4096
)

func (s *Store) ensureAgentRangeAgent(in AgentIdentityInput) (CanonicalAgent, error) {
	cache := &s.agentrangeRuntimeCache
	cache.mu.Lock()
	cached, ok := cache.agents[in.Source]
	cache.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.agent, nil
	}
	agent, err := s.EnsureAgent(in)
	if err != nil {
		return CanonicalAgent{}, err
	}
	cache.mu.Lock()
	if cache.agents == nil {
		cache.agents = make(map[string]cachedAgentRangeAgent, 2)
	}
	cache.agents[in.Source] = cachedAgentRangeAgent{agent: agent, expires: time.Now().Add(agentrangeRuntimeCacheTTL)}
	cache.mu.Unlock()
	return agent, nil
}

func (s *Store) ensureAgentRangeSession(in EnsureRuntimeSessionInput) error {
	cache := &s.agentrangeRuntimeCache
	key := agentrangeSessionKey{agentID: in.CanonicalAgentID, sessionID: in.SessionID}
	cache.mu.Lock()
	expires, ok := cache.sessions[key]
	generation := cache.generation
	cache.mu.Unlock()
	if ok && time.Now().Before(expires) {
		return nil
	}
	if err := s.EnsureRuntimeSession(in); err != nil {
		return err
	}
	cache.mu.Lock()
	if generation != cache.generation {
		cache.mu.Unlock()
		return nil
	}
	if cache.sessions == nil {
		cache.sessions = make(map[agentrangeSessionKey]time.Time)
	}
	if len(cache.sessions) >= agentrangeRuntimeSessionLimit {
		clear(cache.sessions)
	}
	cache.sessions[key] = time.Now().Add(agentrangeRuntimeCacheTTL)
	cache.mu.Unlock()
	return nil
}

func (s *Store) invalidateAgentRangeSession(sessionID string) {
	cache := &s.agentrangeRuntimeCache
	cache.mu.Lock()
	cache.generation++
	for key := range cache.sessions {
		if key.sessionID == sessionID {
			delete(cache.sessions, key)
		}
	}
	cache.mu.Unlock()
}
