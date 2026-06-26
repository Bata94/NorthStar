package hooks

import (
	"testing"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
)

func newForwardingZoneHook(zones []config.ForwardingZoneConfig) *ForwardingZoneHook {
	return NewForwardingZoneHook(zones)
}

func makeFZContext(domain string) *Context {
	return &Context{
		Request: &dns.Message{
			Header: dns.Header{ID: 1, QDCount: 1},
			Questions: []dns.Question{
				{Name: domain, Type: dns.TypeA, Class: 1},
			},
		},
	}
}

func TestForwardingZoneHookExactMatch(t *testing.T) {
	hook := newForwardingZoneHook([]config.ForwardingZoneConfig{
		{Domain: "corp.example.com", Upstreams: []string{"internal"}, Mode: "forward-only"},
	})

	ctx := makeFZContext("corp.example.com.")
	if err := hook.Handle(ctx); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx.PreferredUpstream != "internal" {
		t.Errorf("PreferredUpstream: got %q, want %q", ctx.PreferredUpstream, "internal")
	}
	if !ctx.ForwardOnly {
		t.Error("ForwardOnly should be true for forward-only mode")
	}
}

func TestForwardingZoneHookSuffixMatch(t *testing.T) {
	hook := newForwardingZoneHook([]config.ForwardingZoneConfig{
		{Domain: "internal.corp", Upstreams: []string{"internal-dns"}, Mode: "forward-first"},
	})

	ctx := makeFZContext("db.internal.corp.")
	if err := hook.Handle(ctx); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx.PreferredUpstream != "internal-dns" {
		t.Errorf("PreferredUpstream: got %q, want %q", ctx.PreferredUpstream, "internal-dns")
	}
	if ctx.ForwardOnly {
		t.Error("ForwardOnly should be false for forward-first mode")
	}
}

func TestForwardingZoneHookNoMatch(t *testing.T) {
	hook := newForwardingZoneHook([]config.ForwardingZoneConfig{
		{Domain: "corp.example.com", Upstreams: []string{"internal"}, Mode: "forward-only"},
	})

	ctx := makeFZContext("google.com.")
	if err := hook.Handle(ctx); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx.PreferredUpstream != "" {
		t.Errorf("PreferredUpstream: got %q, want empty", ctx.PreferredUpstream)
	}
	if ctx.ForwardOnly {
		t.Error("ForwardOnly should be false when no match")
	}
}

func TestForwardingZoneHookMultipleZones(t *testing.T) {
	hook := newForwardingZoneHook([]config.ForwardingZoneConfig{
		{Domain: "public.example.com", Upstreams: []string{"public-dns"}, Mode: "forward-first"},
		{Domain: "corp.example.com", Upstreams: []string{"internal"}, Mode: "forward-only"},
	})

	ctx := makeFZContext("corp.example.com.")
	if err := hook.Handle(ctx); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx.PreferredUpstream != "internal" {
		t.Errorf("PreferredUpstream: got %q, want %q", ctx.PreferredUpstream, "internal")
	}
	if !ctx.ForwardOnly {
		t.Error("ForwardOnly should be true for corp zone")
	}

	ctx2 := makeFZContext("public.example.com.")
	if err := hook.Handle(ctx2); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx2.PreferredUpstream != "public-dns" {
		t.Errorf("PreferredUpstream: got %q, want %q", ctx2.PreferredUpstream, "public-dns")
	}
	if ctx2.ForwardOnly {
		t.Error("ForwardOnly should be false for public zone")
	}
}

func TestForwardingZoneHookDisabled(t *testing.T) {
	hook := newForwardingZoneHook(nil)
	if hook.Enabled() {
		t.Error("hook should be disabled with no zones")
	}
}

func TestForwardingZoneHookAXFRPassthrough(t *testing.T) {
	hook := newForwardingZoneHook([]config.ForwardingZoneConfig{
		{Domain: "example.com", Upstreams: []string{"internal"}, Mode: "forward-only"},
	})

	ctx := &Context{
		Request: &dns.Message{
			Header: dns.Header{ID: 1, QDCount: 1},
			Questions: []dns.Question{
				{Name: "example.com.", Type: dns.TypeAXFR, Class: 1},
			},
		},
	}
	if err := hook.Handle(ctx); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx.PreferredUpstream != "" {
		t.Error("AXFR should not be forwarded")
	}
}

func TestForwardingZoneHookEmptyUpstreams(t *testing.T) {
	hook := newForwardingZoneHook([]config.ForwardingZoneConfig{
		{Domain: "example.com", Upstreams: nil, Mode: "forward-only"},
	})

	ctx := makeFZContext("example.com.")
	if err := hook.Handle(ctx); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx.PreferredUpstream != "" {
		t.Error("should not match zone with no upstreams")
	}
}

func TestForwardingZoneHookReplaceZones(t *testing.T) {
	hook := newForwardingZoneHook([]config.ForwardingZoneConfig{
		{Domain: "old.example.com", Upstreams: []string{"old"}, Mode: "forward-only"},
	})

	hook.ReplaceZones([]config.ForwardingZoneConfig{
		{Domain: "new.example.com", Upstreams: []string{"new"}, Mode: "forward-first"},
	})

	ctx := makeFZContext("old.example.com.")
	if err := hook.Handle(ctx); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx.PreferredUpstream != "" {
		t.Error("old zone should not match after replacement")
	}

	ctx2 := makeFZContext("new.example.com.")
	if err := hook.Handle(ctx2); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if ctx2.PreferredUpstream != "new" {
		t.Errorf("new zone should match: got %q, want %q", ctx2.PreferredUpstream, "new")
	}
}

func TestMatchForwardingZone(t *testing.T) {
	tests := []struct {
		domain   string
		zone     string
		expected bool
	}{
		{"corp.example.com", "corp.example.com", true},
		{"db.corp.example.com", "corp.example.com", true},
		{"other.com", "corp.example.com", false},
		{"notcorp.example.com", "corp.example.com", false},
		{"corp.example.com.extra", "corp.example.com", false},
		{"corp.example.com.", "corp.example.com.", true},
		{"example.com", "example.com", true},
		{"sub.example.com", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.domain+"/"+tt.zone, func(t *testing.T) {
			got := matchForwardingZone(tt.domain, tt.zone)
			if got != tt.expected {
				t.Errorf("matchForwardingZone(%q, %q) = %v, want %v", tt.domain, tt.zone, got, tt.expected)
			}
		})
	}
}
