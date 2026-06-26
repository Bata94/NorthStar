package resolver

import (
	"context"
	"net"
	"testing"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/internal/testutil"
)

func BenchmarkResolveCacheMiss(b *testing.B) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(10000, nil)
	defer c.Close()

	mock := testutil.StartMockUpstream(b, "udp", func(data []byte) []byte {
		return testutil.BuildDNSResponse("example.com.", 1, net.ParseIP("1.2.3.4").To4())
	})
	defer mock.Close()

	g := testutil.NewTestGroup(b, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := resolve(ctx, "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "", false)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkResolveCacheHit(b *testing.B) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(10000, nil)
	defer c.Close()

	mock := testutil.StartMockUpstream(b, "udp", func(data []byte) []byte {
		return testutil.BuildDNSResponse("example.com.", 1, net.ParseIP("1.2.3.4").To4())
	})
	defer mock.Close()

	g := testutil.NewTestGroup(b, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	entry := cache.NewEntry("example.com.", 1, 0, []dns.ResourceRecord{{
		Name: "example.com.", Type: 1, Class: 1, TTL: 300,
		RDLength: 4, RData: net.ParseIP("1.2.3.4").To4(),
	}}, nil, nil, 0, 0, 0, 0)
	_ = c.Set(ctx, entry)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := resolve(ctx, "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "", false)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkResolveNXDOMAIN(b *testing.B) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(10000, nil)
	defer c.Close()

	mock := testutil.StartMockUpstream(b, "udp", func(data []byte) []byte {
		return testutil.BuildNXDOMAINResponse("nonexistent.example.com.", 1)
	})
	defer mock.Close()

	g := testutil.NewTestGroup(b, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := resolve(ctx, "nonexistent.example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "", false)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkParseMessage(b *testing.B) {
	data := testutil.BuildDNSResponse("example.com.", 1, net.ParseIP("1.2.3.4").To4())

	b.ResetTimer()
	for b.Loop() {
		var msg dns.Message
		if err := msg.Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPackMessage(b *testing.B) {
	msg := dns.Message{
		Header:    dns.Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []dns.Question{{Name: "example.com.", Type: 1, Class: 1}},
		Answers: []dns.ResourceRecord{{
			Name: "example.com.", Type: 1, Class: 1, TTL: 300,
			RDLength: 4, RData: net.ParseIP("1.2.3.4").To4(),
		}},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = msg.Pack()
	}
}

func BenchmarkResolveConcurrent(b *testing.B) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(10000, nil)
	defer c.Close()

	mock := testutil.StartMockUpstream(b, "udp", func(data []byte) []byte {
		return testutil.BuildDNSResponse("example.com.", 1, net.ParseIP("1.2.3.4").To4())
	})
	defer mock.Close()

	g := testutil.NewTestGroup(b, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := resolve(ctx, "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "", false)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
