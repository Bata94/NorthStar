package zone

import (
	"net"
	"testing"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
)

func TestARecordRData(t *testing.T) {
	r := &ARecord{Name: "test.example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")}
	data, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(data))
	}
	if data[0] != 192 || data[3] != 1 {
		t.Fatalf("unexpected data: %v", data)
	}
}

func TestAAAARecordRData(t *testing.T) {
	r := &AAAARecord{Name: "test.example.com.", TTLSec: 300, IP: net.ParseIP("2001:db8::1")}
	data, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(data))
	}
}

func TestCNAMERecordRData(t *testing.T) {
	r := &CNAMERecord{Name: "www.example.com.", TTLSec: 300, Target: "example.com."}
	data, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 {
		t.Fatalf("expected non-empty rdata, got %d bytes", len(data))
	}
}

func TestMXRecordRData(t *testing.T) {
	r := &MXRecord{Name: "example.com.", TTLSec: 300, Preference: 10, Host: "mail.example.com."}
	data, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 4 {
		t.Fatalf("expected >=4 bytes, got %d", len(data))
	}
	if data[0] != 0 || data[1] != 10 {
		t.Fatalf("expected preference 10, got %d", (int(data[0])<<8)|int(data[1]))
	}
}

func TestSOARecordRData(t *testing.T) {
	r := &SOARecord{
		Name: "example.com.", TTLSec: 3600,
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 20240101, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
	}
	data, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 20 {
		t.Fatalf("expected >=20 bytes, got %d", len(data))
	}
}

func TestTXTRecordRData(t *testing.T) {
	r := &TXTRecord{Name: "example.com.", TTLSec: 300, Data: "hello world"}
	data, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 {
		t.Fatalf("expected >=2 bytes, got %d", len(data))
	}
	if int(data[0]) != len("hello world") {
		t.Fatalf("expected length prefix %d, got %d", len("hello world"), data[0])
	}
}

func TestSRVRecordRData(t *testing.T) {
	r := &SRVRecord{
		Name: "_sip._tcp.example.com.", TTLSec: 300,
		Priority: 10, Weight: 100, Port: 5060, Target: "sip.example.com.",
	}
	data, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 {
		t.Fatalf("expected >=8 bytes, got %d", len(data))
	}
}

func TestZoneLookupExact(t *testing.T) {
	z := New("example.com.", []Record{
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.2")},
	}, nil, nil, nil, nil)

	records, found := z.Lookup("www.example.com.", dns.TypeA)
	if !found {
		t.Fatal("expected to find www.example.com")
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

func TestZoneLookupNotFound(t *testing.T) {
	z := New("example.com.", []Record{
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
	}, nil, nil, nil, nil)

	_, found := z.Lookup("nonexistent.example.com.", dns.TypeA)
	if found {
		t.Fatal("expected not to find nonexistent.example.com")
	}
}

func TestZoneLookupWrongType(t *testing.T) {
	z := New("example.com.", []Record{
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&MXRecord{Name: "example.com.", TTLSec: 300, Preference: 10, Host: "mail.example.com."},
	}, nil, nil, nil, nil)

	records, found := z.Lookup("example.com.", dns.TypeMX)
	if !found {
		t.Fatal("expected to find MX records")
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 MX record, got %d", len(records))
	}
}

func TestZoneLookupANY(t *testing.T) {
	z := New("example.com.", []Record{
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&NSRecord{Name: "example.com.", TTLSec: 3600, Target: "ns1.example.com."},
	}, nil, nil, nil, nil)

	records, found := z.Lookup("example.com.", dns.TypeANY)
	if !found {
		t.Fatal("expected to find ANY records")
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records for ANY, got %d", len(records))
	}
}

func TestBuildResponseAQuery(t *testing.T) {
	z := New("example.com.", []Record{
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
	}, nil, nil, nil, nil)

	req := &dns.Message{
		Header: dns.Header{ID: 42, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: 1},
		},
		Additionals: []dns.ResourceRecord{{
			Name: "", Type: dns.TypeOPT, Class: 1232,
		}},
	}

	resp := BuildResponse(req, z, "example.com.", dns.TypeA)

	if resp.Header.ID != 42 {
		t.Fatalf("expected ID 42, got %d", resp.Header.ID)
	}
	if resp.Header.Flags&0x8000 == 0 {
		t.Fatal("expected QR bit set")
	}
	if resp.Header.Flags&0x0400 == 0 {
		t.Fatal("expected AA bit set")
	}
	if len(resp.Answers) == 0 {
		t.Fatal("expected answers")
	}
	if resp.Answers[0].Type != dns.TypeA {
		t.Fatalf("expected A record, got type %d", resp.Answers[0].Type)
	}
}

func TestBuildResponseNXDOMAIN(t *testing.T) {
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
	}, nil, nil, nil, nil)

	req := &dns.Message{
		Header: dns.Header{ID: 1, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "nonexistent.example.com.", Type: dns.TypeA, Class: 1},
		},
	}

	resp := BuildResponse(req, z, "nonexistent.example.com.", dns.TypeA)
	if resp.Header.Flags&0x0003 != 0x0003 {
		t.Fatal("expected NXDOMAIN rcode")
	}
	if len(resp.Authorities) == 0 {
		t.Fatal("expected SOA in authority for NXDOMAIN")
	}
}

func TestBuildRefusedResponse(t *testing.T) {
	req := &dns.Message{
		Header: dns.Header{ID: 1, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeAXFR, Class: 1},
		},
	}
	resp := BuildRefusedResponse(req)
	if resp.Header.Flags&0x0005 != 0x0005 {
		t.Fatal("expected REFUSED rcode")
	}
}

func TestExpandName(t *testing.T) {
	tests := []struct {
		name, zone, expected string
	}{
		{"@", "example.com.", "example.com."},
		{"www", "example.com.", "www.example.com."},
		{"www.example.com.", "example.com.", "www.example.com."},
		{"", "example.com.", "example.com."},
	}
	for _, tt := range tests {
		result := expandName(tt.name, tt.zone)
		if result != tt.expected {
			t.Errorf("expandName(%q, %q) = %q, want %q", tt.name, tt.zone, result, tt.expected)
		}
	}
}

func TestParseZoneConfigBasic(t *testing.T) {
	zc := config.ZoneConfig{
		Name: "example.com",
		Records: []config.ZoneRecordConfig{
			{
				Name: "@", Type: "SOA", TTL: 3600,
				MName: strPtr("ns1.example.com"), RName: strPtr("admin.example.com"),
				Serial: uint32Ptr(1), Refresh: uint32Ptr(3600),
				Retry: uint32Ptr(900), Expire: uint32Ptr(86400), Minimum: uint32Ptr(3600),
			},
			{
				Name: "@", Type: "A", TTL: 300,
				IP: strPtr("192.0.2.1"),
			},
			{
				Name: "www", Type: "CNAME", TTL: 300,
				Target: strPtr("example.com"),
			},
		},
	}

	z, err := ParseZoneConfig(zc)
	if err != nil {
		t.Fatal(err)
	}
	if z.Name != "example.com." {
		t.Fatalf("expected zone name 'example.com.', got %q", z.Name)
	}
	if len(z.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(z.Records))
	}
}

func TestZoneSetLookup(t *testing.T) {
	z1 := New("example.com.", []Record{
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
	}, nil, nil, nil, nil)
	z2 := New("test.org.", []Record{
		&ARecord{Name: "test.org.", TTLSec: 300, IP: net.ParseIP("198.51.100.1")},
	}, nil, nil, nil, nil)

	s := NewSet([]*Zone{z1, z2})

	if z := s.Lookup("www.example.com."); z == nil {
		t.Fatal("expected to find zone for www.example.com")
	}
	if z := s.Lookup("example.com."); z == nil {
		t.Fatal("expected to find zone for example.com")
	}
	if z := s.Lookup("other.net."); z != nil {
		t.Fatal("expected not to find zone for other.net")
	}
}

func strPtr(s string) *string    { return &s }
func uint32Ptr(u uint32) *uint32 { return &u }
