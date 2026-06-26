package dhcp

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseDnsmasqLeases(t *testing.T) {
	data := `1700000000 00:11:22:33:44:55 192.168.1.100 desktop *
1700000001 aa:bb:cc:dd:ee:ff 192.168.1.101 laptop *
1700000002 11:22:33:44:55:66 192.168.1.102 server *
0 00:00:00:00:00:01 10.0.0.5 static-device *
`
	r := strings.NewReader(data)
	leases, err := ParseLeasesFile(r, "dnsmasq")
	if err != nil {
		t.Fatalf("ParseLeasesFile failed: %v", err)
	}
	if len(leases) != 4 {
		t.Fatalf("expected 4 leases, got %d", len(leases))
	}

	tests := []struct {
		index    int
		hostname string
		ip       string
		mac      string
	}{
		{0, "desktop", "192.168.1.100", "00:11:22:33:44:55"},
		{1, "laptop", "192.168.1.101", "aa:bb:cc:dd:ee:ff"},
		{2, "server", "192.168.1.102", "11:22:33:44:55:66"},
		{3, "static-device", "10.0.0.5", "00:00:00:00:00:01"},
	}

	for _, tt := range tests {
		l := leases[tt.index]
		if l.Hostname != tt.hostname {
			t.Errorf("lease %d hostname: got %q, want %q", tt.index, l.Hostname, tt.hostname)
		}
		if !l.IP.Equal(net.ParseIP(tt.ip)) {
			t.Errorf("lease %d IP: got %v, want %v", tt.index, l.IP, tt.ip)
		}
		if l.MAC != tt.mac {
			t.Errorf("lease %d MAC: got %q, want %q", tt.index, l.MAC, tt.mac)
		}
	}
}

func TestParseDnsmasqLeasesEmpty(t *testing.T) {
	r := strings.NewReader("")
	leases, err := ParseLeasesFile(r, "dnsmasq")
	if err != nil {
		t.Fatalf("ParseLeasesFile failed: %v", err)
	}
	if len(leases) != 0 {
		t.Errorf("expected 0 leases, got %d", len(leases))
	}
}

func TestParseDnsmasqLeasesComments(t *testing.T) {
	data := `# This is a comment
1700000000 00:11:22:33:44:55 192.168.1.100 desktop *
# another comment

1700000001 aa:bb:cc:dd:ee:ff 192.168.1.101 laptop *
`
	r := strings.NewReader(data)
	leases, err := ParseLeasesFile(r, "dnsmasq")
	if err != nil {
		t.Fatalf("ParseLeasesFile failed: %v", err)
	}
	if len(leases) != 2 {
		t.Errorf("expected 2 leases (skipping comments/empty lines), got %d", len(leases))
	}
}

func TestParseDnsmasqLeasesNoHostname(t *testing.T) {
	data := `1700000000 00:11:22:33:44:55 192.168.1.100 * *
`
	r := strings.NewReader(data)
	leases, err := ParseLeasesFile(r, "dnsmasq")
	if err != nil {
		t.Fatalf("ParseLeasesFile failed: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 lease, got %d", len(leases))
	}
	if leases[0].HasHostname() {
		t.Error("lease should not have hostname")
	}
	if leases[0].Hostname != "" {
		t.Errorf("hostname: got %q, want empty", leases[0].Hostname)
	}
}

func TestParseDnsmasqLeasesInvalidLine(t *testing.T) {
	data := `invalid line
1700000000 00:11:22:33:44:55 192.168.1.100 desktop *
`
	r := strings.NewReader(data)
	leases, err := ParseLeasesFile(r, "dnsmasq")
	if err != nil {
		t.Fatalf("ParseLeasesFile failed: %v", err)
	}
	if len(leases) != 1 {
		t.Errorf("expected 1 valid lease, got %d", len(leases))
	}
}

func TestLeaseExpired(t *testing.T) {
	lease := Lease{
		Hostname: "old",
		IP:       net.ParseIP("192.168.1.1"),
		Ends:     time.Now().Add(-1 * time.Hour),
	}
	if !lease.Expired() {
		t.Error("lease should be expired")
	}

	futureLease := Lease{
		Hostname: "active",
		IP:       net.ParseIP("192.168.1.2"),
		Ends:     time.Now().Add(1 * time.Hour),
	}
	if futureLease.Expired() {
		t.Error("lease should not be expired")
	}
}

func TestDnsmasqParserInterface(t *testing.T) {
	var p Parser = DnsmasqParser{}
	data := `1700000000 00:11:22:33:44:55 192.168.1.100 desktop *
`
	r := strings.NewReader(data)
	leases, err := p.Parse(r)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 lease, got %d", len(leases))
	}
}
