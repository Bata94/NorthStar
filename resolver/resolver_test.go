package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
)

func testMetrics() *metrics.Metrics {
	return metrics.New()
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
					if _, err := c.Read(lenBuf); err != nil {
						return
					}
					msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
					data := make([]byte, msgLen)
					if _, err := c.Read(data); err != nil {
						return
					}
					resp := m.handler(data)
					respLen := []byte{byte(len(resp) >> 8), byte(len(resp))}
					_, _ = c.Write(respLen)
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

func (m *mockUpstream) close() {
	if m.closeFn != nil {
		m.closeFn()
	}
}

func mockResponse(queryData []byte, rcode uint16, answers ...dns.ResourceRecord) []byte {
	var req dns.Message
	if err := req.Parse(queryData); err != nil {
		return nil
	}

	flags := uint16(0x8000 | 0x0080 | rcode)
	resp := dns.Message{
		Header: dns.Header{
			ID: req.Header.ID, Flags: flags,
			QDCount: 1, ANCount: uint16(len(answers)),
		},
		Questions: req.Questions,
		Answers:   answers,
	}
	return resp.Pack()
}

func TestStripOPT(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{Name: "example.com", Type: 1, Class: 1},
		{Name: "", Type: 41, Class: 4096},
		{Name: "other.com", Type: 28, Class: 1},
	}
	stripped := stripOPT(rrs)
	if len(stripped) != 2 {
		t.Errorf("expected 2 records, got %d", len(stripped))
	}
	for _, rr := range stripped {
		if rr.Type == 41 {
			t.Error("OPT record should have been stripped")
		}
	}
}

func TestStripOPTNoOPT(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{Name: "example.com", Type: 1, Class: 1},
	}
	stripped := stripOPT(rrs)
	if len(stripped) != 1 {
		t.Errorf("expected 1 record, got %d", len(stripped))
	}
}

func TestClientEDNS(t *testing.T) {
	noOpt := &dns.Message{
		Header: dns.Header{ARCount: 0},
	}
	size, do := clientEDNS(noOpt)
	if size != 512 {
		t.Errorf("default size = %d, want 512", size)
	}
	if do {
		t.Error("default do should be false")
	}

	withOpt := &dns.Message{
		Header: dns.Header{ARCount: 1},
		Additionals: []dns.ResourceRecord{
			{Name: "", Type: 41, Class: 4096, TTL: 0x00008000},
		},
	}
	size, do = clientEDNS(withOpt)
	if size != 4096 {
		t.Errorf("size = %d, want 4096", size)
	}
	if !do {
		t.Error("do should be true")
	}

	withOptNoDO := &dns.Message{
		Header: dns.Header{ARCount: 1},
		Additionals: []dns.ResourceRecord{
			{Name: "", Type: 41, Class: 1234, TTL: 0},
		},
	}
	size, do = clientEDNS(withOptNoDO)
	if size != 1234 {
		t.Errorf("size = %d, want 1234", size)
	}
	if do {
		t.Error("do should be false")
	}
}

func TestResolveCacheHit(t *testing.T) {
	m := cache.NewMemory()
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	entry := cache.NewEntry("example.com", 1,
		[]dns.ResourceRecord{
			{Name: "example.com", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()},
		}, nil, nil)
	_ = m.Set(ctx, entry)

	pool := NewPool("127.0.0.1:9999", "udp", 5, time.Minute)
	defer pool.Close()

	result, err := resolve(ctx, "example.com", 1, "127.0.0.1:9999", m, 512, "udp", 0, pool, false, testMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if result.Domain != "example.com" || len(result.Answers) != 1 {
		t.Error("expected cached entry")
	}
}

func TestResolveCacheMissUpstream(t *testing.T) {
	m := cache.NewMemory()
	defer m.Close() //nolint:errcheck

	up := startMockUpstream(t, "udp", func(data []byte) []byte {
		return mockResponse(data, 0,
			dns.ResourceRecord{Name: "example.com", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()})
	})
	defer up.close()

	pool := NewPool(up.addr.String(), "udp", 5, time.Minute)
	defer pool.Close()

	ctx := context.Background()
	result, err := resolve(ctx, "example.com", 1, up.addr.String(), m, 512, "udp", 0, pool, false, testMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if result.Domain != "example.com" || len(result.Answers) != 1 {
		t.Error("expected fetched entry")
	}

	cached, ok := m.Get(ctx, "example.com", 1)
	if !ok {
		t.Error("entry should be cached")
	}
	if cached.Answers[0].A().String() != "1.2.3.4" {
		t.Error("cached answer mismatch")
	}
}

func TestResolveUpstreamError(t *testing.T) {
	m := cache.NewMemory()
	defer m.Close() //nolint:errcheck

	pool := NewPool("127.0.0.1:1", "udp", 5, time.Minute)
	defer pool.Close()

	ctx := context.Background()
	_, err := resolve(ctx, "example.com", 1, "127.0.0.1:1", m, 512, "udp", 0, pool, false, testMetrics())
	if err == nil {
		t.Fatal("expected error from unreachable upstream")
	}
}

func TestResolveNXDOMAIN(t *testing.T) {
	m := cache.NewMemory()
	defer m.Close() //nolint:errcheck

	up := startMockUpstream(t, "udp", func(data []byte) []byte {
		return mockResponse(data, 3)
	})
	defer up.close()

	pool := NewPool(up.addr.String(), "udp", 5, time.Minute)
	defer pool.Close()

	ctx := context.Background()
	result, err := resolve(ctx, "nonexistent.example", 1, up.addr.String(), m, 512, "udp", 0, pool, false, testMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if result.RCode != 3 {
		t.Errorf("expected NXDOMAIN (3), got %d", result.RCode)
	}
}

func TestResolveStaleWhileRevalidate(t *testing.T) {
	m := cache.NewMemory()
	defer m.Close() //nolint:errcheck

	ctx := context.Background()
	e := cache.NewEntry("stale.example", 1,
		[]dns.ResourceRecord{
			{Name: "stale.example", Type: 1, Class: 1, TTL: 1,
				RDLength: 4, RData: net.ParseIP("9.9.9.9").To4()},
		}, nil, nil)
	e.ExpiresAt = time.Now().Add(-time.Second)
	_ = m.Set(ctx, e)

	up := startMockUpstream(t, "udp", func(data []byte) []byte {
		time.Sleep(50 * time.Millisecond)
		return mockResponse(data, 0,
			dns.ResourceRecord{Name: "stale.example", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()})
	})
	defer up.close()

	pool := NewPool(up.addr.String(), "udp", 5, time.Minute)
	defer pool.Close()

	result, err := resolve(ctx, "stale.example", 1, up.addr.String(), m, 512, "udp", 10, pool, false, testMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Answers) != 1 || result.Answers[0].A().String() != "9.9.9.9" {
		t.Error("expected stale entry to be served")
	}

	time.Sleep(200 * time.Millisecond)

	refreshed, ok := m.Get(ctx, "stale.example", 1)
	if ok && len(refreshed.Answers) > 0 {
		t.Logf("background refresh completed, got: %s", refreshed.Answers[0].A().String())
	}
}

func TestFetchFromUpstreamDNSSEC(t *testing.T) {
	up := startMockUpstream(t, "udp", func(data []byte) []byte {
		var req dns.Message
		if err := req.Parse(data); err != nil {
			return nil
		}

		hasDO := false
		for _, rr := range req.Additionals {
			if rr.Type == 41 && rr.TTL&0x00008000 != 0 {
				hasDO = true
				break
			}
		}

		flags := uint16(0x8000 | 0x0080)
		if hasDO {
			flags |= 0x0020
		}
		resp := dns.Message{
			Header:    dns.Header{ID: req.Header.ID, Flags: flags, QDCount: 1, ANCount: 1},
			Questions: []dns.Question{{Name: "dnssec.example", Type: 1, Class: 1}},
			Answers: []dns.ResourceRecord{
				{Name: "dnssec.example", Type: 1, Class: 1, TTL: 300,
					RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()},
			},
			Additionals: []dns.ResourceRecord{
				{Name: "", Type: 41, Class: 512, TTL: 0x00008000},
			},
		}
		return resp.Pack()
	})
	defer up.close()

	pool := NewPool(up.addr.String(), "udp", 5, time.Minute)
	defer pool.Close()

	ctx := context.Background()
	entry, err := fetchFromUpstream(ctx, "dnssec.example", 1, 512, "udp", pool, true, testMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if !entry.AuthenticData {
		t.Error("expected AuthenticData = true when DO=1 and upstream sets AD")
	}
}

func TestResolveInflightDedup(t *testing.T) {
	m := cache.NewMemory()
	defer m.Close() //nolint:errcheck

	callCount := 0
	up := startMockUpstream(t, "udp", func(data []byte) []byte {
		callCount++
		time.Sleep(100 * time.Millisecond)
		return mockResponse(data, 0,
			dns.ResourceRecord{Name: "inflight.example", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()})
	})
	defer up.close()

	pool := NewPool(up.addr.String(), "udp", 5, time.Minute)
	defer pool.Close()

	ctx := context.Background()
	errs := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := resolve(ctx, "inflight.example", 1, up.addr.String(), m, 512, "udp", 0, pool, false, testMetrics())
			errs <- err
		}()
	}

	for range 3 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	if callCount != 1 {
		t.Errorf("expected 1 upstream call, got %d", callCount)
	}
}

func TestFetchFromUpstreamTCP(t *testing.T) {
	up := startMockUpstream(t, "tcp", func(data []byte) []byte {
		return mockResponse(data, 0,
			dns.ResourceRecord{Name: "tcp.example", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()})
	})
	defer up.close()

	pool := NewPool(up.addr.String(), "tcp", 5, time.Minute)
	defer pool.Close()

	ctx := context.Background()
	entry, err := fetchFromUpstream(ctx, "tcp.example", 1, 512, "tcp", pool, false, testMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.Answers) != 1 {
		t.Error("expected 1 answer")
	}
}
