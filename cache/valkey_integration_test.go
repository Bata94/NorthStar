// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

//go:build integration

package cache

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bata94/northstar/dns"
)

func getValkeyAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Skipf("Valkey not available at %s: %v", addr, err)
		return ""
	}
	c.Close()
	return addr
}

func TestValkeyCacheSetAndGet(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	e := &Entry{
		Domain: "example.com.", QType: 1, RCode: 0,
		ExpiresAt: time.Now().Add(time.Hour),
		Answers:   []dns.ResourceRecord{{Name: "example.com.", Type: 1, Class: 1, TTL: 300, RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()}},
	}

	if err := c.Set(ctx, e); err != nil {
		t.Fatal(err)
	}

	got, ok := c.Get(ctx, "example.com.", 1)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.RCode != 0 {
		t.Errorf("expected RCODE 0, got %d", got.RCode)
	}
	if len(got.Answers) != 1 || !got.Answers[0].A().Equal(net.ParseIP("1.2.3.4")) {
		t.Error("expected A record 1.2.3.4")
	}
}

func TestValkeyCacheGetMiss(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	_, ok := c.Get(ctx, "nonexistent.example.", 1)
	if ok {
		t.Error("expected cache miss")
	}
}

func TestValkeyCachePeek(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	e := &Entry{
		Domain: "peek.example.", QType: 1, RCode: 0,
		ExpiresAt: time.Now().Add(time.Hour),
		Answers:   []dns.ResourceRecord{{Name: "peek.example.", Type: 1, Class: 1, TTL: 300, RDLength: 4, RData: net.ParseIP("5.6.7.8").To4()}},
	}
	if err := c.Set(ctx, e); err != nil {
		t.Fatal(err)
	}

	got, ok := c.Peek(ctx, "peek.example.", 1)
	if !ok {
		t.Fatal("expected peek hit")
	}
	if len(got.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(got.Answers))
	}
}

func TestValkeyCacheDelete(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	e := &Entry{Domain: "del.example.", QType: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := c.Set(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "del.example.", 1); err != nil {
		t.Fatal(err)
	}
	_, ok := c.Get(ctx, "del.example.", 1)
	if ok {
		t.Error("expected cache miss after delete")
	}
}

func TestValkeyCacheDeleteDomain(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	for _, qt := range []uint16{1, 28, 15} {
		e := &Entry{Domain: "multi.example.", QType: qt, ExpiresAt: time.Now().Add(time.Hour)}
		if err := c.Set(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.DeleteDomain(ctx, "multi.example."); err != nil {
		t.Fatal(err)
	}
	for _, qt := range []uint16{1, 28, 15} {
		_, ok := c.Get(ctx, "multi.example.", qt)
		if ok {
			t.Errorf("expected miss for qtype %d after DeleteDomain", qt)
		}
	}
}

func TestValkeyCacheFlush(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e := &Entry{Domain: "flush.test.", QType: uint16(i + 1), ExpiresAt: time.Now().Add(time.Hour)}
		if err := c.Set(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 0 {
		t.Errorf("expected 0 entries after flush, got %d", c.Len())
	}
}

func TestValkeyCacheIncr(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	key := "test:counter:" + strings.ReplaceAll(t.Name(), "/", "_")
	v1, err := c.Incr(ctx, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != 1 {
		t.Errorf("expected 1, got %d", v1)
	}
	v2, err := c.Incr(ctx, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v2 != 2 {
		t.Errorf("expected 2, got %d", v2)
	}
}

func TestValkeyCacheTryLockUnlock(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	c, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	key := "test:lock:" + strings.ReplaceAll(t.Name(), "/", "_")

	locked, err := c.TryLock(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("expected lock acquired")
	}

	locked, err = c.TryLock(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Error("expected lock not re-acquired")
	}

	if err := c.Unlock(ctx, key); err != nil {
		t.Fatal(err)
	}

	locked, err = c.TryLock(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("expected lock re-acquired after unlock")
	}
}

func TestValkeyCacheWarmup(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	v, err := NewValkey(addr, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		domain := "warmup.test."
		e := &Entry{Domain: domain, QType: uint16(i + 1), ExpiresAt: time.Now().Add(time.Hour)}
		if err := v.Set(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	mem := NewMemory(100, nil)
	defer mem.Close()

	if err := v.Warmup(ctx, mem); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		_, ok := mem.Get(ctx, "warmup.test.", uint16(i+1))
		if !ok {
			t.Errorf("expected warmup hit for qtype %d", i+1)
		}
	}
}
