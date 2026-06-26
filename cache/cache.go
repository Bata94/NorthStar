// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package cache

import (
	"container/list"
	"context"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
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
	HitCount      atomic.Int64
	lastHitAt     atomic.Value
}

func (e *Entry) LastHitAt() time.Time {
	if v := e.lastHitAt.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

func (e *Entry) SetLastHitAt(t time.Time) {
	e.lastHitAt.Store(t)
}

func (e *Entry) RecordHit() {
	e.HitCount.Add(1)
	e.SetLastHitAt(time.Now())
}

type Cache interface {
	Get(ctx context.Context, domain string, qtype uint16) (*Entry, bool)
	Peek(ctx context.Context, domain string, qtype uint16) (*Entry, bool)
	Set(ctx context.Context, entry *Entry) error
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Delete(ctx context.Context, domain string, qtype uint16) error
	DeleteDomain(ctx context.Context, domain string) error
	Len() int
	Evictions() int64
	Warmup(ctx context.Context, dest Cache) error
	TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error)
	Unlock(ctx context.Context, key string) error
	Flush(ctx context.Context) error
	Close()
}

func negativeTTLFromSOA(authorities []dns.ResourceRecord, negativeTTLMin, negativeTTLCap int) uint32 {
	var ttl uint32
	found := false
	if negativeTTLCap > 0 {
		ttl = uint32(negativeTTLCap)
		found = true
	}
	if !found {
		for _, rr := range authorities {
			if rr.Type == dns.TypeSOA && len(rr.RData) >= 20 {
				min := binary.BigEndian.Uint32(rr.RData[len(rr.RData)-4:])
				if min > 0 {
					ttl = min
					found = true
					break
				}
			}
		}
	}
	if !found {
		ttl = 300
	}
	if negativeTTLMin > 0 && ttl < uint32(negativeTTLMin) {
		ttl = uint32(negativeTTLMin)
	}
	return ttl
}

func NewEntry(domain string, qtype uint16, rcode uint16, answers, authorities, additionals []dns.ResourceRecord, ttlMin, ttlMax, negativeTTLMin, negativeTTLCap int) *Entry {
	ttl := uint32(defaultTTL)
	isNegative := rcode == 3 || (rcode == 0 && len(answers) == 0)
	if isNegative {
		ttl = negativeTTLFromSOA(authorities, negativeTTLMin, negativeTTLCap)
	} else if len(answers) > 0 {
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
	if ttlMin > 0 && ttl < uint32(ttlMin) {
		ttl = uint32(ttlMin)
	}
	if ttlMax > 0 && ttl > uint32(ttlMax) {
		ttl = uint32(ttlMax)
	}

	e := &Entry{
		Domain:      domain,
		QType:       qtype,
		RCode:       rcode,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
		ExpiresAt:   time.Now().Add(time.Duration(ttl) * time.Second),
	}
	e.HitCount.Store(0)
	return e
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

type PrefetchConfig struct {
	Enable    bool
	Threshold int64
	Window    time.Duration
	Interval  time.Duration
}

type Memory struct {
	entries    map[cacheKey]*list.Element
	lruList    *list.List
	maxEntries int
	mu         sync.Mutex
	counters   map[string]*counterEntry
	countersMu sync.Mutex
	locks      map[string]bool
	locksMu    sync.Mutex
	stopCh     chan struct{}
	evictions  atomic.Int64
	prefetchWg sync.WaitGroup
	metrics    *metrics.Metrics
}

func NewMemory(maxEntries int, m *metrics.Metrics) *Memory {
	mem := &Memory{
		entries:    make(map[cacheKey]*list.Element),
		lruList:    list.New(),
		maxEntries: maxEntries,
		counters:   make(map[string]*counterEntry),
		stopCh:     make(chan struct{}),
		metrics:    m,
		locks:      make(map[string]bool),
	}
	go mem.evictLoop()
	return mem
}

func (m *Memory) Evictions() int64 {
	return m.evictions.Load()
}

func (m *Memory) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			for e := m.lruList.Back(); e != nil; e = e.Prev() {
				entry := e.Value.(*Entry)
				if entry.Expired() {
					delete(m.entries, cacheKey{entry.Domain, entry.QType})
					m.lruList.Remove(e)
					if m.metrics != nil {
						m.metrics.CacheEvictionsTotal.WithLabelValues("memory").Inc()
					}
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

func (m *Memory) evictOne() {
	if m.maxEntries <= 0 || m.lruList.Len() < m.maxEntries {
		return
	}
	for e := m.lruList.Back(); e != nil; e = e.Prev() {
		entry := e.Value.(*Entry)
		if entry.Expired() {
			delete(m.entries, cacheKey{entry.Domain, entry.QType})
			m.lruList.Remove(e)
			return
		}
	}
	e := m.lruList.Back()
	if e != nil {
		entry := e.Value.(*Entry)
		delete(m.entries, cacheKey{entry.Domain, entry.QType})
		m.lruList.Remove(e)
		m.evictions.Add(1)
		if m.metrics != nil {
			m.metrics.CacheEvictionsTotal.WithLabelValues("memory").Inc()
		}
	}
}

func (m *Memory) TryLock(_ context.Context, key string, _ time.Duration) (bool, error) {
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	if m.locks[key] {
		return false, nil
	}
	m.locks[key] = true
	return true, nil
}

func (m *Memory) Unlock(_ context.Context, key string) error {
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	delete(m.locks, key)
	return nil
}

func (m *Memory) Flush(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, el := range m.entries {
		m.lruList.Remove(el)
		delete(m.entries, k)
	}
	return nil
}

func (m *Memory) promote(e *list.Element) {
	m.lruList.MoveToFront(e)
}

func (m *Memory) Get(_ context.Context, domain string, qtype uint16) (*Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.entries[cacheKey{domain, qtype}]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*Entry)
	if entry.Expired() {
		delete(m.entries, cacheKey{domain, qtype})
		m.lruList.Remove(el)
		return nil, false
	}
	m.promote(el)
	return entry, true
}

func (m *Memory) Peek(_ context.Context, domain string, qtype uint16) (*Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.entries[cacheKey{domain, qtype}]
	if !ok {
		return nil, false
	}
	m.promote(el)
	return el.Value.(*Entry), true
}

func (m *Memory) Set(_ context.Context, entry *Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := cacheKey{entry.Domain, entry.QType}
	if el, ok := m.entries[key]; ok {
		m.lruList.Remove(el)
	}
	m.evictOne()
	el := m.lruList.PushFront(entry)
	m.entries[key] = el
	return nil
}

func (m *Memory) Delete(_ context.Context, domain string, qtype uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := cacheKey{domain, qtype}
	if el, ok := m.entries[key]; ok {
		m.lruList.Remove(el)
		delete(m.entries, key)
	}
	return nil
}

func (m *Memory) DeleteDomain(_ context.Context, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, el := range m.entries {
		if key.domain == domain {
			m.lruList.Remove(el)
			delete(m.entries, key)
		}
	}
	return nil
}

func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lruList.Len()
}

func (m *Memory) Warmup(_ context.Context, _ Cache) error {
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

func (m *Memory) StartPrefetch(ctx context.Context, cfg PrefetchConfig, resolveFn func(context.Context, string, uint16) (*Entry, error)) {
	if !cfg.Enable || cfg.Threshold <= 0 || cfg.Window <= 0 || cfg.Interval <= 0 {
		return
	}
	m.prefetchWg.Add(1)
	go func() {
		defer m.prefetchWg.Done()
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.prefetchScan(ctx, cfg, resolveFn)
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			}
		}
	}()
}

func (m *Memory) prefetchScan(ctx context.Context, cfg PrefetchConfig, resolveFn func(context.Context, string, uint16) (*Entry, error)) {
	var candidates []cacheKey

	m.mu.Lock()
	for key, el := range m.entries {
		entry := el.Value.(*Entry)
		if entry.Expired() {
			continue
		}
		if entry.HitCount.Load() < cfg.Threshold {
			continue
		}
		remaining := time.Until(entry.ExpiresAt)
		if remaining > cfg.Window {
			continue
		}
		candidates = append(candidates, key)
	}
	m.mu.Unlock()

	for _, key := range candidates {
		key := key
		if m.metrics != nil {
			m.metrics.PrefetchesTotal.Inc()
		}
		go func() {
			slog.Debug("Prefetching entry", "domain", key.domain, "type", key.qtype)
			if _, err := resolveFn(ctx, key.domain, key.qtype); err != nil {
				slog.Debug("Prefetch failed", "domain", key.domain, "type", key.qtype, "error", err)
			}
		}()
	}
}

type persistEntry struct {
	Domain        string               `json:"domain"`
	QType         uint16               `json:"qtype"`
	Flags         uint16               `json:"flags"`
	RCode         uint16               `json:"rcode"`
	AuthenticData bool                 `json:"authentic_data"`
	Answers       []dns.ResourceRecord `json:"answers"`
	Authorities   []dns.ResourceRecord `json:"authorities"`
	Additionals   []dns.ResourceRecord `json:"additionals"`
	ExpiresAt     time.Time            `json:"expires_at"`
	HitCount      int64                `json:"hit_count"`
	LastHitAt     time.Time            `json:"last_hit_at"`
}

func (m *Memory) Save(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, err := os.CreateTemp("", "northstar-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()

	enc := json.NewEncoder(f)
	for el := m.lruList.Front(); el != nil; el = el.Next() {
		e := el.Value.(*Entry)
		if e.Expired() {
			continue
		}
		pe := persistEntry{
			Domain:        e.Domain,
			QType:         e.QType,
			Flags:         e.Flags,
			RCode:         e.RCode,
			AuthenticData: e.AuthenticData,
			Answers:       e.Answers,
			Authorities:   e.Authorities,
			Additionals:   e.Additionals,
			ExpiresAt:     e.ExpiresAt,
			HitCount:      e.HitCount.Load(),
			LastHitAt:     e.LastHitAt(),
		}
		if err := enc.Encode(pe); err != nil {
			if cerr := f.Close(); cerr != nil {
				slog.Error("Cache save: close temp file after encode error", "error", cerr)
			}
			if rerr := os.Remove(tmpPath); rerr != nil {
				slog.Error("Cache save: remove temp file after encode error", "path", tmpPath, "error", rerr)
			}
			return err
		}
	}
	if err := f.Close(); err != nil {
		if rerr := os.Remove(tmpPath); rerr != nil {
			slog.Error("Cache save: remove temp file after close error", "path", tmpPath, "error", rerr)
		}
		return err
	}
	return os.Rename(tmpPath, path)
}

func (m *Memory) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			slog.Error("Cache load: close file", "path", path, "error", err)
		}
	}()

	dec := json.NewDecoder(f)
	for dec.More() {
		var pe persistEntry
		if err := dec.Decode(&pe); err != nil {
			return err
		}
		if time.Now().After(pe.ExpiresAt) {
			continue
		}
		e := &Entry{
			Domain:        pe.Domain,
			QType:         pe.QType,
			Flags:         pe.Flags,
			RCode:         pe.RCode,
			AuthenticData: pe.AuthenticData,
			Answers:       pe.Answers,
			Authorities:   pe.Authorities,
			Additionals:   pe.Additionals,
			ExpiresAt:     pe.ExpiresAt,
		}
		e.HitCount.Store(pe.HitCount)
		e.SetLastHitAt(pe.LastHitAt)
		m.mu.Lock()
		key := cacheKey{e.Domain, e.QType}
		if el, ok := m.entries[key]; ok {
			m.lruList.Remove(el)
		}
		m.evictOne()
		el := m.lruList.PushFront(e)
		m.entries[key] = el
		m.mu.Unlock()
	}
	return nil
}

func (m *Memory) Close() {
	close(m.stopCh)
	m.prefetchWg.Wait()
}
