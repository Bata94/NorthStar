// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package cache

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bata94/northstar/dns"
)

func makeA(name string, ttl uint32, ip string) dns.ResourceRecord {
	return dns.ResourceRecord{
		Name: name, Type: 1, Class: 1, TTL: ttl,
		RDLength: 4, RData: net.ParseIP(ip).To4(),
	}
}

func makeCNAME(name, target string, ttl uint32) dns.ResourceRecord {
	data := []byte{byte(len(target))}
	data = append(data, []byte(target)...)
	data = append(data, 0)
	return dns.ResourceRecord{
		Name: name, Type: 5, Class: 1, TTL: ttl,
		RDLength: uint16(len(data)), RData: data,
	}
}

func makeSOA(ttl uint32) dns.ResourceRecord {
	rdata := []byte{
		2, 'n', 's', 0,
		2, 'a', 'd', 0,
		0, 0, 0, 0x3C,
		0, 0, 0x0E, 0x10,
		0, 0x00, 0x09, 0x3A,
		0x80, 0, 0x00, 0x01,
		0, 0, 0, 0x78,
	}
	return dns.ResourceRecord{
		Name: "example.com", Type: 6, Class: 1, TTL: ttl,
		RDLength: uint16(len(rdata)), RData: rdata,
	}
}

func TestNewEntryTTLFromMatchingType(t *testing.T) {
	entry := NewEntry("example.com", 1, 0,
		[]dns.ResourceRecord{
			makeA("example.com", 300, "1.2.3.4"),
			makeA("example.com", 600, "5.6.7.8"),
		}, nil, nil, 0, 0, 0, 0)
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 299*time.Second || remaining > 301*time.Second {
		t.Errorf("expected TTL ~300s (min of A records), got %v", remaining)
	}
}

func TestNewEntryDefaultTTLFallback(t *testing.T) {
	entry := NewEntry("example.com", 1, 0, nil, nil, nil, 0, 0, 0, 0)
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 299*time.Second || remaining > 301*time.Second {
		t.Errorf("expected TTL ~300s (negative TTL default), got %v", remaining)
	}
}

func TestNewEntryEmptyAnswersSoaFallback(t *testing.T) {
	soa := makeSOA(120)
	entry := NewEntry("example.com", 1, 0, nil,
		[]dns.ResourceRecord{soa}, nil, 0, 0, 0, 0)
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 119*time.Second || remaining > 121*time.Second {
		t.Errorf("expected TTL ~120s (from SOA), got %v", remaining)
	}
}

func TestNewEntryMixedTTLCNAMEAndA(t *testing.T) {
	entry := NewEntry("www.example.com", 1, 0,
		[]dns.ResourceRecord{
			makeCNAME("www.example.com", "example.com", 1200),
			makeA("example.com", 300, "1.2.3.4"),
		}, nil, nil, 0, 0, 0, 0)
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 299*time.Second || remaining > 301*time.Second {
		t.Errorf("expected TTL ~300s (from A record matching qtype=1), got %v", remaining)
	}
}

func TestNewEntryNoMatchingType(t *testing.T) {
	entry := NewEntry("example.com", 1, 0,
		[]dns.ResourceRecord{
			{Name: "example.com", Type: 5, Class: 1, TTL: 100},
		}, nil, nil, 0, 0, 0, 0)
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 3599*time.Second || remaining > 3601*time.Second {
		t.Errorf("expected TTL ~3600s (defaultTTL, no matching type), got %v", remaining)
	}
}

func TestNewEntryZeroTTL(t *testing.T) {
	entry := NewEntry("example.com", 1, 0,
		[]dns.ResourceRecord{
			makeA("example.com", 0, "1.2.3.4"),
		}, nil, nil, 0, 0, 0, 0)
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 3599*time.Second || remaining > 3601*time.Second {
		t.Errorf("expected TTL ~3600s (defaultTTL for zero TTL), got %v", remaining)
	}
}

func TestEntryExpired(t *testing.T) {
	e := &Entry{ExpiresAt: time.Now().Add(-time.Second)}
	if !e.Expired() {
		t.Error("expected expired")
	}
	e.ExpiresAt = time.Now().Add(time.Hour)
	if e.Expired() {
		t.Error("expected not expired")
	}
}

func TestCopyRecordsWithAdjustedTTL(t *testing.T) {
	e := &Entry{
		ExpiresAt: time.Now().Add(100 * time.Second),
		Answers: []dns.ResourceRecord{
			{Name: "example.com", Type: 1, Class: 1, TTL: 9999, RDLength: 4, RData: []byte{1, 2, 3, 4}},
		},
		Authorities: []dns.ResourceRecord{
			{Name: "example.com", Type: 6, Class: 1, TTL: 8888},
		},
		Additionals: []dns.ResourceRecord{
			{Name: "", Type: dns.TypeOPT, Class: 4096, TTL: 7777},
		},
	}
	answers, authorities, additionals := e.CopyRecordsWithAdjustedTTL()

	if len(answers) != 1 || answers[0].TTL < 99 || answers[0].TTL > 100 {
		t.Errorf("answers TTL: got %d, want ~100", answers[0].TTL)
	}
	if len(authorities) != 1 || authorities[0].TTL < 99 || authorities[0].TTL > 100 {
		t.Errorf("authorities TTL: got %d, want ~100", authorities[0].TTL)
	}
	if len(additionals) != 1 || additionals[0].TTL < 99 || additionals[0].TTL > 100 {
		t.Errorf("additionals TTL: got %d, want ~100", additionals[0].TTL)
	}

	if answers[0].RDLength != 4 {
		t.Error("RData should be preserved")
	}
}

func TestCopyRecordsFloorOneSecond(t *testing.T) {
	e := &Entry{ExpiresAt: time.Now().Add(-time.Second)}
	answers, _, _ := e.CopyRecordsWithAdjustedTTL()
	if len(answers) > 0 && answers[0].TTL < 1 {
		t.Errorf("TTL should be floored at 1s, got %d", answers[0].TTL)
	}
}

func TestMemoryGetSet(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close()

	ctx := context.Background()
	e := NewEntry("example.com", 1, 0,
		[]dns.ResourceRecord{makeA("example.com", 300, "1.2.3.4")}, nil, nil, 0, 0, 0, 0)
	_ = m.Set(ctx, e)

	got, ok := m.Get(ctx, "example.com", 1)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Domain != "example.com" {
		t.Errorf("domain = %s", got.Domain)
	}
	if len(got.Answers) != 1 {
		t.Errorf("answers = %d", len(got.Answers))
	}
}

func TestMemoryGetMiss(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close()
	_, ok := m.Get(context.Background(), "nonexistent", 1)
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestMemoryPeek(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close()

	ctx := context.Background()
	e := NewEntry("example.com", 1, 0,
		[]dns.ResourceRecord{makeA("example.com", 300, "1.2.3.4")}, nil, nil, 0, 0, 0, 0)
	_ = m.Set(ctx, e)

	got, ok := m.Peek(ctx, "example.com", 1)
	if !ok {
		t.Fatal("expected peek hit")
	}
	if got.Answers[0].TTL != e.Answers[0].TTL {
		t.Error("Peek should return original TTL")
	}
}

func TestMemoryPeekExpired(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	e := &Entry{
		Domain: "expired.example", QType: 1,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	_ = m.Set(ctx, e)

	got, ok := m.Peek(ctx, "expired.example", 1)
	if !ok {
		t.Fatal("Peek should return expired entry")
	}
	if got == nil {
		t.Fatal("Peek should return entry even if expired")
	}
}

func TestMemoryGetDeletesExpired(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	e := &Entry{
		Domain: "stale.example", QType: 1,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	_ = m.Set(ctx, e)

	_, ok := m.Get(ctx, "stale.example", 1)
	if ok {
		t.Fatal("Get should not return expired entry")
	}

	_, ok = m.Peek(ctx, "stale.example", 1)
	if ok {
		t.Fatal("Peek should not find entry after Get deleted it")
	}
}

func TestMemoryIncr(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	v, err := m.Incr(ctx, "test:key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("first Incr = %d, want 1", v)
	}

	v, err = m.Incr(ctx, "test:key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v != 2 {
		t.Errorf("second Incr = %d, want 2", v)
	}
}

func TestMemoryIncrExpiry(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	_, _ = m.Incr(ctx, "ephemeral", time.Millisecond*50)
	time.Sleep(time.Millisecond * 100)
	v, err := m.Incr(ctx, "ephemeral", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("after expiry Incr = %d, want 1", v)
	}
}

func TestMemoryConcurrentAccess(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			domain := "test.example"
			e := NewEntry(domain, 1, 0, []dns.ResourceRecord{makeA(domain, 300, "1.2.3.4")}, nil, nil, 0, 0, 0, 0)
			_ = m.Set(ctx, e)
			m.Get(ctx, domain, 1)
			_, _ = m.Incr(ctx, "concurrent:key", time.Minute)
		}(i)
	}
	wg.Wait()
}

func buildSOARDATA(minimum uint32) []byte {
	mname := []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0}
	rname := []byte{10, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r', 0}
	rdata := make([]byte, len(mname)+len(rname)+20)
	copy(rdata[0:], mname)
	copy(rdata[len(mname):], rname)
	off := len(mname) + len(rname)
	for _, v := range []uint32{2026000001, 3600, 900, 86400, minimum} {
		rdata[off] = byte(v >> 24)
		rdata[off+1] = byte(v >> 16)
		rdata[off+2] = byte(v >> 8)
		rdata[off+3] = byte(v)
		off += 4
	}
	return rdata
}

func TestNegativeCacheEntryNXDOMAIN(t *testing.T) {
	rdata := buildSOARDATA(300)
	auth := []dns.ResourceRecord{{
		Name: "example.com.", Type: dns.TypeSOA, Class: 1,
		TTL: 3600, RDLength: uint16(len(rdata)), RData: rdata,
	}}

	e := NewEntry("example.com.", 1, dns.RcodeNXDOMAIN, nil, auth, nil, 0, 0, 0, 0)
	if e.RCode != dns.RcodeNXDOMAIN {
		t.Errorf("expected RCODE %d, got %d", dns.RcodeNXDOMAIN, e.RCode)
	}
	expectedTTL := time.Duration(300) * time.Second
	remaining := time.Until(e.ExpiresAt)
	if remaining < expectedTTL-time.Second || remaining > expectedTTL+time.Second {
		t.Errorf("expected TTL ~%v, got expiresAt=%v (remaining=%v)", expectedTTL, e.ExpiresAt, remaining)
	}
}

func TestNegativeCacheEntryNODATA(t *testing.T) {
	rdata := buildSOARDATA(120)
	auth := []dns.ResourceRecord{{
		Name: "example.com.", Type: dns.TypeSOA, Class: 1,
		TTL: 3600, RDLength: uint16(len(rdata)), RData: rdata,
	}}

	e := NewEntry("example.com.", 1, dns.RcodeSuccess, nil, auth, nil, 0, 0, 0, 0)
	if e.RCode != dns.RcodeSuccess {
		t.Errorf("expected RCODE 0, got %d", e.RCode)
	}
	expectedTTL := time.Duration(120) * time.Second
	remaining := time.Until(e.ExpiresAt)
	if remaining < expectedTTL-time.Second || remaining > expectedTTL+time.Second {
		t.Errorf("expected TTL ~%v, got expiresAt=%v (remaining=%v)", expectedTTL, e.ExpiresAt, remaining)
	}
}

func TestNegativeCacheEntryConfigurableOverride(t *testing.T) {
	e := NewEntry("example.com.", 1, dns.RcodeNXDOMAIN, nil, nil, nil, 0, 0, 0, 60)
	expectedTTL := time.Duration(60) * time.Second
	remaining := time.Until(e.ExpiresAt)
	if remaining < expectedTTL-time.Second || remaining > expectedTTL+time.Second {
		t.Errorf("expected TTL ~%v, got expiresAt=%v (remaining=%v)", expectedTTL, e.ExpiresAt, remaining)
	}
}

func TestMemoryLazyEviction(t *testing.T) {
	m := NewMemory(0, nil)
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	e := &Entry{
		Domain: "old.example", QType: 1,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	_ = m.Set(ctx, e)

	_, ok := m.Get(ctx, "old.example", 1)
	if ok {
		t.Fatal("Get should not return expired entry")
	}

	_, ok = m.Peek(ctx, "old.example", 1)
	if ok {
		t.Fatal("Get should have deleted the expired entry")
	}
}
