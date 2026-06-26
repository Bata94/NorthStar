package hooks

import (
	"net"
	"testing"
	"time"

	"github.com/bata94/northstar/dhcp"
	"github.com/bata94/northstar/dns"
)

func nowPlus(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

func newDHCPHook(leases []dhcp.Lease) *DHCPHook {
	w := dhcp.NewWatcher("/dev/null", "dnsmasq", 3600)
	hook := NewDHCPHook(w, "lan", 300)
	return hook
}

func makeDHCPCtx(domain string, qtype uint16, send func([]byte) error) *Context {
	return &Context{
		Request: &dns.Message{
			Header: dns.Header{ID: 1, Flags: 0x0100, QDCount: 1},
			Questions: []dns.Question{
				{Name: domain, Type: qtype, Class: 1},
			},
		},
		Send: send,
	}
}

func dhcpTestLeases() []dhcp.Lease {
	return []dhcp.Lease{
		{Hostname: "desktop", IP: net.ParseIP("192.168.1.100"), MAC: "00:11:22:33:44:55", Ends: nowPlus(3600)},
		{Hostname: "laptop", IP: net.ParseIP("192.168.1.101"), MAC: "aa:bb:cc:dd:ee:ff", Ends: nowPlus(3600)},
		{Hostname: "server", IP: net.ParseIP("10.0.0.5"), MAC: "11:22:33:44:55:66", Ends: nowPlus(3600)},
	}
}

func TestDHCPHookResolveHostname(t *testing.T) {
	leases := dhcpTestLeases()
	answers := resolveDHCPQuery("desktop.lan", dns.TypeA, leases, "lan", 300)
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
	if answers[0].Type != dns.TypeA {
		t.Errorf("expected A record, got type %d", answers[0].Type)
	}
	if !net.IP(answers[0].RData).Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("expected IP 192.168.1.100, got %v", net.IP(answers[0].RData))
	}
}

func TestDHCPHookResolveHostnameNoMatch(t *testing.T) {
	leases := dhcpTestLeases()
	answers := resolveDHCPQuery("unknown.lan", dns.TypeA, leases, "lan", 300)
	if len(answers) != 0 {
		t.Errorf("expected 0 answers for unknown host, got %d", len(answers))
	}
}

func TestDHCPHookResolveHostnameWrongDomain(t *testing.T) {
	leases := dhcpTestLeases()
	answers := resolveDHCPQuery("desktop.other", dns.TypeA, leases, "lan", 300)
	if len(answers) != 0 {
		t.Errorf("expected 0 answers for wrong domain, got %d", len(answers))
	}
}

func TestDHCPHookResolvePTR(t *testing.T) {
	leases := dhcpTestLeases()
	answers := resolveDHCPQuery("100.1.168.192.in-addr.arpa", dns.TypePTR, leases, "lan", 300)
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
	if answers[0].Type != dns.TypePTR {
		t.Errorf("expected PTR record, got type %d", answers[0].Type)
	}
}

func TestDHCPHookResolvePTRNoMatch(t *testing.T) {
	leases := dhcpTestLeases()
	answers := resolveDHCPQuery("200.1.168.192.in-addr.arpa", dns.TypePTR, leases, "lan", 300)
	if len(answers) != 0 {
		t.Errorf("expected 0 answers for unknown IP, got %d", len(answers))
	}
}

func TestDHCPHookResolvePTRBadFormat(t *testing.T) {
	leases := dhcpTestLeases()
	answers := resolveDHCPQuery("not-a-ptr", dns.TypePTR, leases, "lan", 300)
	if len(answers) != 0 {
		t.Errorf("expected 0 answers for bad PTR format, got %d", len(answers))
	}
}

func TestDHCPHookResolveUnsupportedType(t *testing.T) {
	leases := dhcpTestLeases()
	answers := resolveDHCPQuery("desktop.lan", dns.TypeMX, leases, "lan", 300)
	if len(answers) != 0 {
		t.Errorf("expected 0 answers for unsupported type, got %d", len(answers))
	}
}

func TestDHCPHookHandleEnabled(t *testing.T) {
	hook := newDHCPHook(dhcpTestLeases())
	if !hook.Enabled() {
		t.Error("hook should be enabled")
	}
}

func TestDHCPHookName(t *testing.T) {
	hook := newDHCPHook(nil)
	if hook.Name() != "dhcp" {
		t.Errorf("Name: got %q, want %q", hook.Name(), "dhcp")
	}
}

func TestDHCPHookPriority(t *testing.T) {
	hook := newDHCPHook(nil)
	if hook.Priority() != 45 {
		t.Errorf("Priority: got %d, want 45", hook.Priority())
	}
}

func TestDHCPHookHandlePassthrough(t *testing.T) {
	hook := NewDHCPHook(nil, "lan", 300)
	if hook.Enabled() {
		t.Error("nil watcher hook should be disabled")
	}

	ctx := makeDHCPCtx("desktop.lan.", dns.TypeA, nil)
	err := hook.Handle(ctx)
	if err != nil {
		t.Errorf("expected nil error for disabled hook, got %v", err)
	}
}

func TestDHCPHookExpiredLease(t *testing.T) {
	w := dhcp.NewWatcher("/dev/null", "dnsmasq", 3600)
	hook := NewDHCPHook(w, "lan", 300)

	var sent bool
	ctx := makeDHCPCtx("old.lan.", dns.TypeA, func(data []byte) error {
		sent = true
		return nil
	})

	err := hook.Handle(ctx)
	if err == ErrHookStop {
		t.Error("expected no response for expired lease")
	}
	if sent {
		t.Error("expected no response sent for expired lease")
	}
}
