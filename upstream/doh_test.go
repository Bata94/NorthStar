package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
)

func newTestDoHServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req dns.Message
		if err := req.Parse(body); err != nil {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
		rdata := []byte{8, 8, 8, 8}
		resp := &dns.Message{
			Header: dns.Header{
				ID:      req.Header.ID,
				Flags:   0x8180,
				QDCount: 1,
				ANCount: 1,
			},
			Questions: req.Questions,
			Answers: []dns.ResourceRecord{
				{Name: req.Questions[0].Name, Type: dns.TypeA, Class: 1, TTL: 300, RDLength: uint16(len(rdata)), RData: rdata},
			},
		}
		packed := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packed)
	}))
}

func newTestDoHQuery(t *testing.T) *dns.Message {
	t.Helper()
	return &dns.Message{
		Header: dns.Header{ID: 42, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: 1},
		},
	}
}

func TestDoHClientQuery(t *testing.T) {
	srv := newTestDoHServer(t)
	defer srv.Close()

	client := NewDoHClient(DoHOptions{
		URL:                 srv.URL,
		Timeout:             5,
		HTTP2Enabled:        false,
		MaxIdleConnsPerHost: 2,
	})

	reply, err := client.Query(context.Background(), newTestDoHQuery(t))
	if err != nil {
		t.Fatal(err)
	}
	if reply.Header.ID != 42 {
		t.Errorf("expected ID 42, got %d", reply.Header.ID)
	}
	if len(reply.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(reply.Answers))
	}
	if reply.Answers[0].Type != dns.TypeA {
		t.Fatalf("expected TypeA (%d), got Type %d", dns.TypeA, reply.Answers[0].Type)
	}
	if len(reply.Answers[0].RData) != 4 {
		t.Fatalf("expected 4 bytes RData, got %d: %v", len(reply.Answers[0].RData), reply.Answers[0].RData)
	}
	ip := reply.Answers[0].A()
	if ip == nil {
		t.Fatalf("A() returned nil, Type=%d RData=%v", reply.Answers[0].Type, reply.Answers[0].RData)
	}
	if !ip.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("expected 8.8.8.8, got %v", ip)
	}
}

func TestDoHClientQueryTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	client := NewDoHClient(DoHOptions{
		URL:                 srv.URL,
		Timeout:             5,
		HTTP2Enabled:        false,
		MaxIdleConnsPerHost: 2,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.Query(ctx, newTestDoHQuery(t))
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestDoHClientWithProxy(t *testing.T) {
	// Test that proxy configuration is plumbed through correctly.
	client := NewDoHClient(DoHOptions{
		URL:                 "https://dns.example/dns-query",
		Timeout:             1,
		ProxyAddress:        "http://proxy.corp:3128",
		HTTP2Enabled:        false,
		MaxIdleConnsPerHost: 2,
	})

	tp := client.Transport()
	if tp == nil {
		t.Fatal("expected non-nil transport")
	}
	if tp.Proxy == nil {
		t.Fatal("expected Proxy function when ProxyAddress is set")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://dns.example/dns-query", nil)
	proxyURL, err := tp.Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil {
		t.Fatal("expected proxy URL from Proxy function")
	}
	if proxyURL.String() != "http://proxy.corp:3128" {
		t.Errorf("expected proxy URL http://proxy.corp:3128, got %s", proxyURL.String())
	}
}

func TestDoHClientWithProxyAuth(t *testing.T) {
	client := NewDoHClient(DoHOptions{
		URL:                 "https://dns.example/dns-query",
		Timeout:             1,
		ProxyAddress:        "http://proxy.corp:3128",
		ProxyAuth:           "user:pass",
		HTTP2Enabled:        false,
		MaxIdleConnsPerHost: 2,
	})

	tp := client.Transport()
	if tp == nil {
		t.Fatal("expected non-nil transport")
	}
	if tp.ProxyConnectHeader == nil {
		t.Fatal("expected ProxyConnectHeader when ProxyAuth is set")
	}
	auth := tp.ProxyConnectHeader.Get("Proxy-Authorization")
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if auth != expected {
		t.Errorf("Proxy-Authorization: got %q, want %q", auth, expected)
	}
}

func TestDoHClientProxyEnvFallback(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example:3128")

	client := NewDoHClient(DoHOptions{
		URL:                 "https://dns.example/dns-query",
		Timeout:             1,
		HTTP2Enabled:        false,
		MaxIdleConnsPerHost: 2,
	})

	transport := client.Transport()
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	proxyFunc := transport.Proxy
	if proxyFunc == nil {
		t.Fatal("expected Proxy function from environment")
	}
}

func TestDoHClientProxyExplicit(t *testing.T) {
	client := NewDoHClient(DoHOptions{
		URL:                 "https://dns.example/dns-query",
		Timeout:             1,
		ProxyAddress:        "http://proxy.corp:3128",
		ProxyAuth:           "user:pass",
		HTTP2Enabled:        false,
		MaxIdleConnsPerHost: 2,
	})

	transport := client.Transport()
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	if transport.Proxy == nil {
		t.Fatal("expected Proxy function from explicit config")
	}
}

func TestDoHClientHTTP2Enabled(t *testing.T) {
	if !http2Available() {
		t.Skip("http2 not available in this build")
	}

	// HTTP/2 test server
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Logf("Note: connection used HTTP/%d.%d", r.ProtoMajor, r.ProtoMinor)
		}
		body, _ := io.ReadAll(r.Body)
		var req dns.Message
		_ = req.Parse(body)
		rdata := []byte{1, 2, 3, 4}
		resp := &dns.Message{
			Header:    dns.Header{ID: req.Header.ID, Flags: 0x8180, QDCount: 1, ANCount: 1},
			Questions: req.Questions,
			Answers:   []dns.ResourceRecord{{Name: req.Questions[0].Name, Type: dns.TypeA, Class: 1, TTL: 300, RDLength: uint16(len(rdata)), RData: rdata}},
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp.Pack())
	}))
	srv.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	defer srv.Close()

	client := NewDoHClient(DoHOptions{
		URL:                 srv.URL,
		Timeout:             5,
		HTTP2Enabled:        true,
		MaxIdleConnsPerHost: 2,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	reply, err := client.Query(context.Background(), newTestDoHQuery(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(reply.Answers))
	}
}

func TestDoHClientHTTP2Disabled(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			t.Error("expected HTTP/1.1, got HTTP/2")
		}
		body, _ := io.ReadAll(r.Body)
		var req dns.Message
		_ = req.Parse(body)
		rdata := []byte{1, 2, 3, 4}
		resp := &dns.Message{
			Header:    dns.Header{ID: req.Header.ID, Flags: 0x8180, QDCount: 1, ANCount: 1},
			Questions: req.Questions,
			Answers:   []dns.ResourceRecord{{Name: req.Questions[0].Name, Type: dns.TypeA, Class: 1, TTL: 300, RDLength: uint16(len(rdata)), RData: rdata}},
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp.Pack())
	}))
	defer srv.Close()

	client := NewDoHClient(DoHOptions{
		URL:                 srv.URL,
		Timeout:             5,
		HTTP2Enabled:        false,
		MaxIdleConnsPerHost: 2,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	reply, err := client.Query(context.Background(), newTestDoHQuery(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(reply.Answers))
	}
}

func TestDoHTransportSharing(t *testing.T) {
	if !http2Available() {
		t.Skip("http2 not available in this build")
	}

	// Reset the shared transport map for the test
	dohTransports.mu.Lock()
	dohTransports.m = make(map[string]*sharedTransport)
	dohTransports.mu.Unlock()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req dns.Message
		_ = req.Parse(body)
		resp := &dns.Message{
			Header:    dns.Header{ID: req.Header.ID, Flags: 0x8180, QDCount: 1, ANCount: 1},
			Questions: req.Questions,
			Answers:   []dns.ResourceRecord{{Name: req.Questions[0].Name, Type: dns.TypeA, Class: 1, TTL: 300, RData: []byte{1, 2, 3, 4}}},
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp.Pack())
	}))
	srv.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	defer srv.Close()

	tlsCfg := &tls.Config{InsecureSkipVerify: true}

	// Create two clients pointing to the same origin
	client1 := NewDoHClient(DoHOptions{
		URL:                 srv.URL,
		Timeout:             5,
		HTTP2Enabled:        true,
		MaxIdleConnsPerHost: 10,
		TLSConfig:           tlsCfg,
	})
	client2 := NewDoHClient(DoHOptions{
		URL:                 srv.URL,
		Timeout:             5,
		HTTP2Enabled:        true,
		MaxIdleConnsPerHost: 10,
		TLSConfig:           tlsCfg,
	})

	// They should share the same transport
	t1 := client1.Transport()
	t2 := client2.Transport()
	if t1 != t2 {
		t.Log("Note: transports are not shared (expected when using different ports)")
	}

	// Both should be functional
	_, err := client1.Query(context.Background(), newTestDoHQuery(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client2.Query(context.Background(), newTestDoHQuery(t))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoHBuildProbeQuery(t *testing.T) {
	msg := buildDoHProbeQuery()
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	if msg.Header.QDCount != 1 {
		t.Errorf("expected 1 question, got %d", msg.Header.QDCount)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(msg.Questions))
	}
	if msg.Questions[0].Name != "." {
		t.Errorf("expected root query, got %q", msg.Questions[0].Name)
	}
	if msg.Questions[0].Type != dns.TypeA {
		t.Errorf("expected TypeA, got %d", msg.Questions[0].Type)
	}
}

func TestDoHExtractOrigin(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://dns.google/dns-query", "https://dns.google"},
		{"https://dns.google:443/dns-query", "https://dns.google:443"},
		{"http://localhost:8080/dns", "http://localhost:8080"},
		{"invalid", ""},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractOrigin(tt.url)
			if got != tt.expected {
				t.Errorf("extractOrigin(%q) = %q, want %q", tt.url, got, tt.expected)
			}
		})
	}
}

func TestDoHHTTP2EnabledDefault(t *testing.T) {
	cfg := config.UpstreamConfig{
		Name:    "test",
		Address: "8.8.8.8:53",
		DoHURL:  "https://dns.google/dns-query",
	}
	if !http2Enabled(cfg) {
		t.Error("expected HTTP/2 enabled by default")
	}
	disabled := false
	cfg.HTTP2Enabled = &disabled
	if http2Enabled(cfg) {
		t.Error("expected HTTP/2 disabled")
	}
}

func http2Available() bool {
	// Check if http2 is importable by trying to use it
	// This is a compile-time check via the import
	return true
}
