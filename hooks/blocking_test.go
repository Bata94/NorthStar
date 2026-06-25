package hooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
)

func writeTestList(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBlockingHookBlocksDomain(t *testing.T) {
	blockPath := writeTestList(t, "bad.com\n*.evil.net\n")

	m := metrics.New()
	mem := cache.NewMemory(0)
	defer mem.Close()

	hook, err := NewBlockingHook(struct {
		Enabled      bool
		Priority     int
		BlockAction  string
		SinkholeAddr string
		Blocklists   []string
		Allowlists   []string
		DomainRPS    int
		RPZ          []struct{ Path, Action string }
	}{
		Enabled:      true,
		Priority:     200,
		BlockAction:  "nxdomain",
		SinkholeAddr: "127.0.0.1",
		Blocklists:   []string{blockPath},
	}, m)
	if err != nil {
		t.Fatal(err)
	}

	sent := false
	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "bad.com", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.1",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send: func(_ []byte) error {
			sent = true
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrBlocked {
		t.Errorf("expected ErrBlocked, got %v", err)
	}
	if !sent {
		t.Error("expected response to be sent for blocked domain")
	}
}

func TestBlockingHookAllowlist(t *testing.T) {
	blockPath := writeTestList(t, "bad.com\n")
	allowPath := writeTestList(t, "sub.bad.com\n")

	m := metrics.New()
	mem := cache.NewMemory(0)
	defer mem.Close()

	hook, err := NewBlockingHook(struct {
		Enabled      bool
		Priority     int
		BlockAction  string
		SinkholeAddr string
		Blocklists   []string
		Allowlists   []string
		DomainRPS    int
		RPZ          []struct{ Path, Action string }
	}{
		Enabled:     true,
		Priority:    200,
		BlockAction: "nxdomain",
		Blocklists:  []string{blockPath},
		Allowlists:  []string{allowPath},
	}, m)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "sub.bad.com", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.1",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send:     func(_ []byte) error { return nil },
	}

	if err := hook.Handle(ctx); err != nil {
		t.Errorf("expected nil (allowed), got %v", err)
	}
}

func TestBlockingHookSinkhole(t *testing.T) {
	blockPath := writeTestList(t, "tracked.com\n")

	m := metrics.New()
	mem := cache.NewMemory(0)
	defer mem.Close()

	hook, err := NewBlockingHook(struct {
		Enabled      bool
		Priority     int
		BlockAction  string
		SinkholeAddr string
		Blocklists   []string
		Allowlists   []string
		DomainRPS    int
		RPZ          []struct{ Path, Action string }
	}{
		Enabled:      true,
		Priority:     200,
		BlockAction:  "sinkhole",
		SinkholeAddr: "127.0.0.1",
		Blocklists:   []string{blockPath},
	}, m)
	if err != nil {
		t.Fatal(err)
	}

	var sentData []byte
	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "tracked.com", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.1",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send: func(data []byte) error {
			sentData = make([]byte, len(data))
			copy(sentData, data)
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrBlocked {
		t.Errorf("expected ErrBlocked, got %v", err)
	}
	if sentData == nil {
		t.Fatal("expected response data")
	}

	var resp dns.Message
	if err := resp.Parse(sentData); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Flags&0x000F != 0 {
		t.Errorf("expected NOERROR (rcode 0), got %d", resp.Header.Flags&0x000F)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
}

func TestBlockingHookDrop(t *testing.T) {
	blockPath := writeTestList(t, "drop.me\n")

	m := metrics.New()
	mem := cache.NewMemory(0)
	defer mem.Close()

	hook, err := NewBlockingHook(struct {
		Enabled      bool
		Priority     int
		BlockAction  string
		SinkholeAddr string
		Blocklists   []string
		Allowlists   []string
		DomainRPS    int
		RPZ          []struct{ Path, Action string }
	}{
		Enabled:     true,
		Priority:    200,
		BlockAction: "drop",
		Blocklists:  []string{blockPath},
	}, m)
	if err != nil {
		t.Fatal(err)
	}

	sent := false
	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "drop.me", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.1",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send: func(_ []byte) error {
			sent = true
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrBlocked {
		t.Errorf("expected ErrBlocked, got %v", err)
	}
	if sent {
		t.Error("expected no response for drop action")
	}
}

func TestBlockingHookNotBlocked(t *testing.T) {
	blockPath := writeTestList(t, "bad.com\n")

	m := metrics.New()
	mem := cache.NewMemory(0)
	defer mem.Close()

	hook, err := NewBlockingHook(struct {
		Enabled      bool
		Priority     int
		BlockAction  string
		SinkholeAddr string
		Blocklists   []string
		Allowlists   []string
		DomainRPS    int
		RPZ          []struct{ Path, Action string }
	}{
		Enabled:     true,
		Priority:    200,
		BlockAction: "nxdomain",
		Blocklists:  []string{blockPath},
	}, m)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "good.com", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.1",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send:     func(_ []byte) error { return nil },
	}

	if err := hook.Handle(ctx); err != nil {
		t.Errorf("expected nil for unblocked domain, got %v", err)
	}
}

func TestBlockingHookDisabled(t *testing.T) {
	m := metrics.New()

	hook, err := NewBlockingHook(struct {
		Enabled      bool
		Priority     int
		BlockAction  string
		SinkholeAddr string
		Blocklists   []string
		Allowlists   []string
		DomainRPS    int
		RPZ          []struct{ Path, Action string }
	}{
		Enabled: false,
	}, m)
	if err != nil {
		t.Fatal(err)
	}
	if hook.Enabled() {
		t.Error("disabled hook should not be enabled")
	}
}

func TestBlockingHookRefused(t *testing.T) {
	blockPath := writeTestList(t, "refused.com\n")

	m := metrics.New()
	mem := cache.NewMemory(0)
	defer mem.Close()

	hook, err := NewBlockingHook(struct {
		Enabled      bool
		Priority     int
		BlockAction  string
		SinkholeAddr string
		Blocklists   []string
		Allowlists   []string
		DomainRPS    int
		RPZ          []struct{ Path, Action string }
	}{
		Enabled:     true,
		Priority:    200,
		BlockAction: "refused",
		Blocklists:  []string{blockPath},
	}, m)
	if err != nil {
		t.Fatal(err)
	}

	var sentData []byte
	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "refused.com", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.1",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send: func(data []byte) error {
			sentData = make([]byte, len(data))
			copy(sentData, data)
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrBlocked {
		t.Errorf("expected ErrBlocked, got %v", err)
	}
	if sentData == nil {
		t.Fatal("expected response data")
	}

	var resp dns.Message
	if err := resp.Parse(sentData); err != nil {
		t.Fatal(err)
	}
	if rcode := resp.Header.Flags & 0x000F; rcode != 5 {
		t.Errorf("expected REFUSED (rcode 5), got %d", rcode)
	}
}
