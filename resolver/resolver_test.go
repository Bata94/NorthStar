// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/upstream"
)

func testMetrics() *metrics.Metrics {
	return metrics.New()
}

func testRuntimeConfig(staleAge int) *config.RuntimeConfig {
	rc := config.NewRuntimeConfig(&config.Config{
		StaleAge: staleAge,
		Hooks: config.HookConfig{
			RateLimiting: config.RateLimitHookConfig{Enabled: false},
		},
	})
	return rc
}

type mockUpstream struct {
	t       *testing.T
	network string
	handler func(data []byte) []byte
	addr    net.Addr
	closeFn func()
}

func startMockUpstream(t *testing.T, network string, handler func(data []byte) []byte) *mockUpstream {
	t.Helper()
	m := &mockUpstream{t: t, network: network, handler: handler}

	switch network {
	case "tcp":
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		m.addr = l.Addr()
		m.closeFn = func() { _ = l.Close() }
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer func() { _ = c.Close() }()
					lenBuf := make([]byte, 2)
					if _, err := io.ReadFull(c, lenBuf); err != nil {
						return
					}
					msgLen := binary.BigEndian.Uint16(lenBuf)
					data := make([]byte, msgLen)
					if _, err := io.ReadFull(c, data); err != nil {
						return
					}
					resp := m.handler(data)
					lenPref := make([]byte, 2)
					binary.BigEndian.PutUint16(lenPref, uint16(len(resp)))
					_, _ = c.Write(lenPref)
					_, _ = c.Write(resp)
				}(conn)
			}
		}()
	default:
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		m.addr = conn.LocalAddr()
		m.closeFn = func() { _ = conn.Close() }
		go func() {
			buf := make([]byte, 1500)
			for {
				n, rAddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				resp := m.handler(buf[:n])
				_, _ = conn.WriteToUDP(resp, rAddr)
			}
		}()
	}

	return m
}

func (m *mockUpstream) Close() {
	if m.closeFn != nil {
		m.closeFn()
	}
}

func (m *mockUpstream) Addr() string {
	return m.addr.String()
}

func testGroup(t *testing.T, addr string) *upstream.Group {
	t.Helper()
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{{
			Name:           "test",
			Address:        addr,
			Priority:       0,
			Timeout:        5,
			HealthCheck:    false,
			HealthInterval: 30,
			HealthTimeout:  5,
			MaxFails:       3,
			Weight:         1,
		}},
		UpstreamPoolSize: 10,
		UpstreamPoolIdle: 30,
	}
	g, err := upstream.NewGroup(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func testResponse(t *testing.T, domain string, qtype uint16) []byte {
	t.Helper()
	rdata := []byte{0}
	switch qtype {
	case 1:
		rdata = net.ParseIP("1.2.3.4").To4()
	case 28:
		rdata = net.ParseIP("::1").To16()
	}
	msg := dns.Message{
		Header: dns.Header{
			ID:      0,
			Flags:   0x8000,
			QDCount: 1,
			ANCount: 1,
		},
		Questions: []dns.Question{{Name: domain, Type: qtype, Class: 1}},
		Answers: []dns.ResourceRecord{{
			Name:     domain,
			Type:     qtype,
			Class:    1,
			TTL:      300,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		}},
	}
	return msg.Pack()
}

func testNXDOMAINResponse(t *testing.T, domain string, qtype uint16) []byte {
	t.Helper()
	msg := dns.Message{
		Header: dns.Header{
			ID:      0,
			Flags:   0x8003,
			QDCount: 1,
		},
		Questions: []dns.Question{{Name: domain, Type: qtype, Class: 1}},
	}
	return msg.Pack()
}

func TestResolveCacheHit(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(0)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	mock := startMockUpstream(t, "udp", func(data []byte) []byte {
		return testResponse(t, "example.com.", 1)
	})
	defer mock.Close()

	g := testGroup(t, mock.Addr())
	defer g.Close()

	ip := net.ParseIP("1.2.3.4").To4()
	cachedEntry := cache.NewEntry("example.com.", 1, 0,
		[]dns.ResourceRecord{{
			Name: "example.com.", Type: 1, Class: 1, TTL: 300,
			RDLength: uint16(len(ip)),
			RData:    ip,
		}}, nil, nil, 0, 0, 0)
	_ = c.Set(context.Background(), cachedEntry)

	result, upstreamName, err := resolve(context.Background(), "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil entry")
	}
	if len(result.Answers) == 0 || len(cachedEntry.Answers) == 0 {
		t.Fatal("expected answers in both entries")
	}
	if result.Answers[0].RData[0] != cachedEntry.Answers[0].RData[0] {
		t.Error("expected cached entry")
	}
	if upstreamName != "" {
		t.Errorf("expected empty upstream name for cache hit, got %s", upstreamName)
	}
}

func TestResolveCacheMissUpstream(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(0)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	mock := startMockUpstream(t, "udp", func(data []byte) []byte {
		return testResponse(t, "example.com.", 1)
	})
	defer mock.Close()

	g := testGroup(t, mock.Addr())
	defer g.Close()

	result, upstreamName, err := resolve(context.Background(), "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil entry")
	}
	if len(result.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(result.Answers))
	}
	if upstreamName != "test" {
		t.Errorf("expected upstream name 'test', got %s", upstreamName)
	}

	cached, found := c.Peek(context.Background(), "example.com.", 1)
	if !found {
		t.Fatal("expected entry to be cached")
	}
	if len(cached.Answers) != 1 {
		t.Errorf("expected 1 cached answer, got %d", len(cached.Answers))
	}
}

func TestResolveUpstreamError(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(0)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	g := testGroup(t, "127.0.0.1:1")
	defer g.Close()

	_, _, err := resolve(context.Background(), "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
	if err == nil {
		t.Fatal("expected error for unreachable upstream")
	}
}

func TestResolveNXDOMAIN(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(0)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	mock := startMockUpstream(t, "udp", func(data []byte) []byte {
		return testNXDOMAINResponse(t, "nonexistent.example.com.", 1)
	})
	defer mock.Close()

	g := testGroup(t, mock.Addr())
	defer g.Close()

	result, _, err := resolve(context.Background(), "nonexistent.example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil entry")
	}
	if result.RCode != 3 {
		t.Errorf("expected RCODE 3 (NXDOMAIN), got %d", result.RCode)
	}
}

func TestResolveStaleWhileRevalidate(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(10)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	mock := startMockUpstream(t, "udp", func(data []byte) []byte {
		return testResponse(t, "example.com.", 1)
	})
	defer mock.Close()

	g := testGroup(t, mock.Addr())
	defer g.Close()

	ip5 := net.ParseIP("5.6.7.8").To4()
	staleEntry := cache.NewEntry("example.com.", 1, 0,
		[]dns.ResourceRecord{{
			Name: "example.com.", Type: 1, Class: 1, TTL: 1,
			RDLength: uint16(len(ip5)),
			RData:    ip5,
		}}, nil, nil, 0, 0, 0)
	staleEntry.ExpiresAt = time.Now().Add(-1 * time.Second)
	_ = c.Set(context.Background(), staleEntry)

	time.Sleep(10 * time.Millisecond)

	result, _, err := resolve(context.Background(), "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil entry (stale)")
	}
	if len(result.Answers) == 0 || len(staleEntry.Answers) == 0 {
		t.Fatal("expected answers in both entries")
	}
	if result.Answers[0].RData[0] != staleEntry.Answers[0].RData[0] {
		t.Error("expected stale entry (pre-refresh)")
	}
}

func TestResolveInflightDedup(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(0)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	var callCount atomic.Int64
	mock := startMockUpstream(t, "udp", func(data []byte) []byte {
		callCount.Add(1)
		time.Sleep(50 * time.Millisecond)
		return testResponse(t, "example.com.", 1)
	})
	defer mock.Close()

	g := testGroup(t, mock.Addr())
	defer g.Close()

	ctx := context.Background()
	results := make(chan *entryResult, 3)
	for i := 0; i < 3; i++ {
		go func() {
			entry, _, err := resolve(ctx, "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
			results <- &entryResult{entry: entry, err: err}
		}()
	}

	for i := 0; i < 3; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.entry == nil {
			t.Fatal("expected non-nil entry")
		}
	}

	if callCount.Load() != 1 {
		t.Errorf("expected 1 upstream call (inflight dedup), got %d", callCount.Load())
	}
}

type entryResult struct {
	entry *cache.Entry
	err   error
}

func TestFetchFromUpstreamTCP(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(0)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	mock := startMockUpstream(t, "tcp", func(data []byte) []byte {
		return testResponse(t, "example.com.", 1)
	})
	defer mock.Close()

	g := testGroup(t, mock.Addr())
	defer g.Close()

	result, _, err := resolve(context.Background(), "example.com.", 1, g, c, 512, "tcp", rc, false, m, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil entry")
	}
	if len(result.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(result.Answers))
	}
}

func TestFetchFromUpstreamDNSSEC(t *testing.T) {
	m := testMetrics()
	rc := testRuntimeConfig(0)
	c := cache.NewMemory(0, nil)
	defer c.Close()

	mock := startMockUpstream(t, "udp", func(data []byte) []byte {
		return testResponse(t, "example.com.", 1)
	})
	defer mock.Close()

	g := testGroup(t, mock.Addr())
	defer g.Close()

	result, _, err := resolve(context.Background(), "example.com.", 1, g, c, 512, "udp", rc, true, m, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil entry")
	}
}

func TestStripOPT(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: 1},
		{Name: "", Type: dns.TypeOPT, Class: 512},
	}
	result := stripOPT(rrs)
	if len(result) != 1 {
		t.Errorf("expected 1 record after strip, got %d", len(result))
	}
}

func TestStripOPTNoOPT(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: 1},
	}
	result := stripOPT(rrs)
	if len(result) != 1 {
		t.Errorf("expected 1 record after strip, got %d", len(result))
	}
}

func TestClientEDNS(t *testing.T) {
	req := &dns.Message{
		Additionals: []dns.ResourceRecord{
			{Name: "", Type: dns.TypeOPT, Class: 1232, TTL: 0x00008000},
		},
	}
	size, do, ver := clientEDNS(req)
	if size != 1232 {
		t.Errorf("expected size 1232, got %d", size)
	}
	if !do {
		t.Error("expected DO bit set")
	}
	if ver != 0 {
		t.Errorf("expected version 0, got %d", ver)
	}
}

func TestClientEDNSVersionNonZero(t *testing.T) {
	req := &dns.Message{
		Additionals: []dns.ResourceRecord{
			{Name: "", Type: dns.TypeOPT, Class: 4096, TTL: 0x00010000},
		},
	}
	_, _, ver := clientEDNS(req)
	if ver != 1 {
		t.Errorf("expected version 1, got %d", ver)
	}
}

func TestBuildBADVERSPacket(t *testing.T) {
	req := &dns.Message{
		Header: dns.Header{ID: 42},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: 1},
		},
	}
	packed := buildBADVERSPacket(req, 1232)
	var resp dns.Message
	if err := resp.Parse(packed); err != nil {
		t.Fatal(err)
	}
	if resp.Header.ID != 42 {
		t.Errorf("expected ID 42, got %d", resp.Header.ID)
	}
	if resp.Header.Flags&0x000F != 0 {
		t.Errorf("expected header RCODE 0 (extended RCODE=16), got %d", resp.Header.Flags&0x000F)
	}
	if resp.Header.Flags&0x8000 == 0 {
		t.Error("expected QR bit set")
	}
	if len(resp.Additionals) != 1 || resp.Additionals[0].Type != dns.TypeOPT {
		t.Error("expected OPT record in additional")
	}
	if resp.Additionals[0].Class != 1232 {
		t.Errorf("expected maxPayload 1232, got %d", resp.Additionals[0].Class)
	}
	extRcode := resp.Additionals[0].TTL >> 24
	if extRcode != dns.RcodeBADVERS>>4 {
		t.Errorf("expected extended RCODE %d, got %d", dns.RcodeBADVERS>>4, extRcode)
	}
	optVersion := (resp.Additionals[0].TTL >> 16) & 0xFF
	if optVersion != 0 {
		t.Errorf("expected OPT version 0, got %d", optVersion)
	}
}

func TestClientEDNSNoOPT(t *testing.T) {
	req := &dns.Message{}
	size, do, ver := clientEDNS(req)
	if size != 512 {
		t.Errorf("expected default size 512, got %d", size)
	}
	if do {
		t.Error("expected DO bit not set")
	}
	if ver != 0 {
		t.Errorf("expected version 0, got %d", ver)
	}
}

func TestClientEDNSCustomSize(t *testing.T) {
	req := &dns.Message{
		Additionals: []dns.ResourceRecord{
			{Name: "", Type: dns.TypeOPT, Class: 4096},
		},
	}
	size, do, ver := clientEDNS(req)
	if size != 4096 {
		t.Errorf("expected size 4096, got %d", size)
	}
	if do {
		t.Error("expected DO bit not set")
	}
	if ver != 0 {
		t.Errorf("expected version 0, got %d", ver)
	}
}
