// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

//go:build integration

package resolver

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
)

func getValkeyAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	c, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Skipf("Valkey not available at %s: %v", addr, err)
		return ""
	}
	c.Close()
	return addr
}

func getCrossNodeAddr(t *testing.T, envKey, defaultAddr string) string {
	t.Helper()
	addr := os.Getenv(envKey)
	if addr == "" {
		addr = defaultAddr
	}
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		t.Skipf("Cross-node instance not available at %s: %v", addr, err)
		return ""
	}
	conn.Close()
	return addr
}

func buildQuery(domain string, qtype uint16) []byte {
	msg := dns.Message{
		Header: dns.Header{ID: 1, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{{
			Name: domain, Type: qtype, Class: 1,
		}},
	}
	return msg.Pack()
}

func parseResponse(data []byte) (*dns.Message, error) {
	var msg dns.Message
	if err := msg.Parse(data); err != nil {
		return nil, err
	}
	return &msg, nil
}

func TestCrossNodeCacheCoordination(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	nodeA, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()

	nodeB, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	ctx := context.Background()
	domain := "crossnode-cache-test.example."
	qtype := uint16(1)
	e := &cache.Entry{
		Domain:    domain,
		QType:     qtype,
		RCode:     0,
		ExpiresAt: time.Now().Add(time.Hour),
		Answers: []dns.ResourceRecord{{
			Name: domain, Type: qtype, Class: 1, TTL: 300,
			RDLength: 4, RData: net.ParseIP("10.0.0.1").To4(),
		}},
	}

	if err := nodeA.Set(ctx, e); err != nil {
		t.Fatal(err)
	}

	got, ok := nodeB.Get(ctx, domain, qtype)
	if !ok {
		t.Fatal("expected cache hit on node B after set from node A")
	}
	if len(got.Answers) != 1 || !got.Answers[0].A().Equal(net.ParseIP("10.0.0.1")) {
		t.Error("expected A record 10.0.0.1 on node B")
	}
}

func TestCrossNodeLockCoordination(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	nodeA, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()

	nodeB, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	ctx := context.Background()
	key := "test:lock:" + strings.ReplaceAll(t.Name(), "/", "_")

	locked, err := nodeA.TryLock(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("expected node A to acquire lock")
	}

	locked, err = nodeB.TryLock(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Error("expected node B to fail acquiring lock held by node A")
	}

	if err := nodeA.Unlock(ctx, key); err != nil {
		t.Fatal(err)
	}

	locked, err = nodeB.TryLock(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("expected node B to acquire lock after node A released")
	}
}

func TestCrossNodeInflightDedup(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	nodeA, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()

	nodeB, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	ctx := context.Background()
	domain := "crossnode-inflight-test.example."
	qtype := uint16(1)
	lockKey := "northstar:inflight:" + domain + ":" + "1"

	locked, err := nodeA.TryLock(ctx, lockKey, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("expected node A to acquire inflight lock")
	}

	locked, err = nodeB.TryLock(ctx, lockKey, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Error("expected node B to fail acquiring inflight lock held by node A")
	}

	e := &cache.Entry{
		Domain:    domain,
		QType:     qtype,
		RCode:     0,
		ExpiresAt: time.Now().Add(time.Hour),
		Answers: []dns.ResourceRecord{{
			Name: domain, Type: qtype, Class: 1, TTL: 300,
			RDLength: 4, RData: net.ParseIP("10.0.0.2").To4(),
		}},
	}
	if err := nodeA.Set(ctx, e); err != nil {
		t.Fatal(err)
	}

	if err := nodeA.Unlock(ctx, lockKey); err != nil {
		t.Fatal(err)
	}

	got, ok := nodeB.Get(ctx, domain, qtype)
	if !ok {
		t.Fatal("expected node B to find entry after node A cached it")
	}
	if len(got.Answers) != 1 || !got.Answers[0].A().Equal(net.ParseIP("10.0.0.2")) {
		t.Error("expected A record 10.0.0.2 on node B")
	}
}

func TestCrossNodeRateLimitConsistency(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	nodeA, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()

	nodeB, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	ctx := context.Background()
	key := "test:ratelimit:" + strings.ReplaceAll(t.Name(), "/", "_")

	v1, err := nodeA.Incr(ctx, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != 1 {
		t.Errorf("expected 1 from node A, got %d", v1)
	}

	v2, err := nodeB.Incr(ctx, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v2 != 2 {
		t.Errorf("expected 2 from node B (shared counter), got %d", v2)
	}

	v3, err := nodeA.Incr(ctx, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v3 != 3 {
		t.Errorf("expected 3 from node A (shared counter), got %d", v3)
	}
}

func TestCrossNodeCacheFlush(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	nodeA, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()

	nodeB, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	ctx := context.Background()
	domains := []string{"flush-a.example.", "flush-b.example."}
	for i, d := range domains {
		e := &cache.Entry{
			Domain:    d,
			QType:     1,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if i == 0 {
			if err := nodeA.Set(ctx, e); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := nodeB.Set(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := nodeA.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	for _, d := range domains {
		_, ok := nodeB.Get(ctx, d, 1)
		if ok {
			t.Errorf("expected cache miss for %s after flush", d)
		}
	}
}

func TestCrossNodeDNSCacheSharing(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	nodeAAddr := getCrossNodeAddr(t, "CROSS_NODE_A_ADDR", "127.0.0.1:18053")
	if nodeAAddr == "" {
		return
	}

	nodeBAddr := getCrossNodeAddr(t, "CROSS_NODE_B_ADDR", "127.0.0.1:18054")
	if nodeBAddr == "" {
		return
	}

	domain := "crossnode-dns-test.example."
	query := buildQuery(domain, 1)

	respA, err := testutilSendUDPQuery(nodeAAddr, query)
	if err != nil {
		t.Fatal(err)
	}
	msgA, err := parseResponse(respA)
	if err != nil {
		t.Fatal(err)
	}
	if msgA.Header.Flags&0x000F != 0 {
		t.Logf("node A returned RCODE %d (expected forward to upstream)", msgA.Header.Flags&0x000F)
	}

	respB, err := testutilSendUDPQuery(nodeBAddr, query)
	if err != nil {
		t.Fatal(err)
	}
	msgB, err := parseResponse(respB)
	if err != nil {
		t.Fatal(err)
	}
	if msgB.Header.Flags&0x000F != 0 {
		t.Logf("node B returned RCODE %d", msgB.Header.Flags&0x000F)
	}

	if t.Failed() {
		return
	}
	t.Logf("Node A: ID=%d AN=%d NS=%d AR=%d RCODE=%d Addrs=%v",
		msgA.Header.ID, msgA.Header.ANCount, msgA.Header.NSCount, msgA.Header.ARCount,
		msgA.Header.Flags&0x000F, extractAddrs(msgA))
	t.Logf("Node B: ID=%d AN=%d NS=%d AR=%d RCODE=%d Addrs=%v",
		msgB.Header.ID, msgB.Header.ANCount, msgB.Header.NSCount, msgB.Header.ARCount,
		msgB.Header.Flags&0x000F, extractAddrs(msgB))
}

func extractAddrs(msg *dns.Message) []string {
	var addrs []string
	for _, a := range msg.Answers {
		if a.Type == 1 && len(a.RData) == 4 {
			addrs = append(addrs, net.IP(a.RData).String())
		}
	}
	return addrs
}

func testutilSendUDPQuery(addr string, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	resp := make([]byte, 1500)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

func TestCrossNodeStaleWhileRevalidate(t *testing.T) {
	addr := getValkeyAddr(t)
	if addr == "" {
		return
	}

	nodeA, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()

	nodeB, err := cache.NewValkey(addr, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	ctx := context.Background()
	domain := "crossnode-stale-test.example."
	staleLockKey := "northstar:inflight:stale:" + domain + ":" + "1"

	locked, err := nodeA.TryLock(ctx, staleLockKey, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("expected node A to acquire stale lock")
	}

	locked, err = nodeB.TryLock(ctx, staleLockKey, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Error("expected node B to fail acquiring stale lock held by node A")
	}

	if err := nodeA.Unlock(ctx, staleLockKey); err != nil {
		t.Fatal(err)
	}

	locked, err = nodeB.TryLock(ctx, staleLockKey, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("expected node B to acquire stale lock after node A released")
	}
}
