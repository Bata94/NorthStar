// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package cache

import (
	"context"
	"sync"
	"time"

	"github.com/bata94/northstar/dns"
)

const defaultTTL = 3600

type cacheKey struct {
	domain string
	qtype  uint16
}

type Entry struct {
	Domain        string
	QType         uint16
	Flags         uint16
	RCode         uint16
	AuthenticData bool
	Answers       []dns.ResourceRecord
	Authorities   []dns.ResourceRecord
	Additionals   []dns.ResourceRecord
	ExpiresAt     time.Time
}

type Cache interface {
	Get(ctx context.Context, domain string, qtype uint16) (*Entry, bool)
	Peek(ctx context.Context, domain string, qtype uint16) (*Entry, bool)
	Set(ctx context.Context, entry *Entry) error
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Close() error
}

func NewEntry(domain string, qtype uint16, answers, authorities, additionals []dns.ResourceRecord) *Entry {
	ttl := uint32(defaultTTL)
	if len(answers) > 0 {
		matched := false
		for _, rr := range answers {
			if rr.Type == qtype {
				if !matched {
					ttl = rr.TTL
					matched = true
				} else if rr.TTL < ttl {
					ttl = rr.TTL
				}
			}
		}
		if !matched {
			ttl = defaultTTL
		}
	} else {
		for _, rr := range authorities {
			if rr.TTL < ttl {
				ttl = rr.TTL
			}
		}
		for _, rr := range additionals {
			if rr.TTL < ttl {
				ttl = rr.TTL
			}
		}
	}
	if ttl == 0 {
		ttl = defaultTTL
	}

	return &Entry{
		Domain:      domain,
		QType:       qtype,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
		ExpiresAt:   time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (e *Entry) Expired() bool {
	return time.Now().After(e.ExpiresAt)
}

func (e *Entry) CopyRecordsWithAdjustedTTL() (answers, authorities, additionals []dns.ResourceRecord) {
	remaining := time.Until(e.ExpiresAt)
	if remaining < time.Second {
		remaining = time.Second
	}
	ttl := uint32(remaining.Seconds())

	adjust := func(rrs []dns.ResourceRecord) []dns.ResourceRecord {
		out := make([]dns.ResourceRecord, len(rrs))
		for i, rr := range rrs {
			out[i] = rr
			out[i].TTL = ttl
		}
		return out
	}

	return adjust(e.Answers), adjust(e.Authorities), adjust(e.Additionals)
}

type counterEntry struct {
	value     int64
	expiresAt time.Time
}

type Memory struct {
	entries    map[cacheKey]*Entry
	mu         sync.RWMutex
	counters   map[string]*counterEntry
	countersMu sync.Mutex
	stopCh     chan struct{}
}

func NewMemory() *Memory {
	m := &Memory{
		entries:  make(map[cacheKey]*Entry),
		counters: make(map[string]*counterEntry),
		stopCh:   make(chan struct{}),
	}
	go m.evictLoop()
	return m
}

func (m *Memory) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			for k, e := range m.entries {
				if e.Expired() {
					delete(m.entries, k)
				}
			}
			m.mu.Unlock()

			m.countersMu.Lock()
			now := time.Now()
			for k, ce := range m.counters {
				if now.After(ce.expiresAt) {
					delete(m.counters, k)
				}
			}
			m.countersMu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Memory) Get(_ context.Context, domain string, qtype uint16) (*Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[cacheKey{domain, qtype}]
	if ok && entry.Expired() {
		delete(m.entries, cacheKey{domain, qtype})
		return nil, false
	}
	return entry, ok
}

func (m *Memory) Peek(_ context.Context, domain string, qtype uint16) (*Entry, bool) {
	m.mu.RLock()
	entry, ok := m.entries[cacheKey{domain, qtype}]
	m.mu.RUnlock()
	return entry, ok
}

func (m *Memory) Set(_ context.Context, entry *Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[cacheKey{entry.Domain, entry.QType}] = entry
	return nil
}

func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.countersMu.Lock()
	defer m.countersMu.Unlock()

	ce, ok := m.counters[key]
	if !ok || time.Now().After(ce.expiresAt) {
		ce = &counterEntry{
			expiresAt: time.Now().Add(ttl),
		}
		m.counters[key] = ce
	}

	ce.value++
	return ce.value, nil
}

func (m *Memory) Close() error {
	close(m.stopCh)
	return nil
}
