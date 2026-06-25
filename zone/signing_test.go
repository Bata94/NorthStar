package zone

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"net"
	"testing"

	"github.com/bata94/northstar/dns"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey("", dns.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestPublicKeyToWireECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := PublicKeyToWire(&key.PublicKey, dns.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 64 {
		t.Fatalf("expected 64 bytes for P-256 pubkey, got %d", len(wire))
	}
}

func TestComputeKeyTag(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := PublicKeyToWire(&key.PublicKey, dns.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	tag := ComputeKeyTag(wire, dns.AlgECDSAP256, "example.com.")
	if tag == 0 {
		t.Fatal("expected non-zero key tag")
	}
}

func TestSignAndVerifyRRSIG(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	zoneName := "example.com."
	records := []Record{
		&ARecord{Name: zoneName, TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
	}

	wire, err := PublicKeyToWire(&key.PublicKey, dns.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	tag := ComputeKeyTag(wire, dns.AlgECDSAP256, zoneName)

	rrsig, err := SignRRset(records, zoneName, key, dns.AlgECDSAP256, tag)
	if err != nil {
		t.Fatal(err)
	}
	if rrsig == nil {
		t.Fatal("expected non-nil RRSIG")
	}
	if rrsig.TypeCovered != dns.TypeA {
		t.Fatalf("expected TypeCovered=A(1), got %d", rrsig.TypeCovered)
	}
	if rrsig.KeyTag != tag {
		t.Fatalf("expected key tag %d, got %d", tag, rrsig.KeyTag)
	}
	if len(rrsig.Signature) == 0 {
		t.Fatal("expected non-empty signature")
	}

	rrsigData, err := rrsig.RData()
	if err != nil {
		t.Fatal(err)
	}

	parsedSig, err := dns.ParseRRSIG(&dns.ResourceRecord{RData: rrsigData, Type: dns.TypeRRSIG})
	if err != nil {
		t.Fatalf("ParseRRSIG: %v", err)
	}

	rrset := []dns.ResourceRecord{recordToRR(records[0])}
	if err := dns.VerifyRRSIG(rrset, parsedSig, &key.PublicKey); err != nil {
		t.Fatalf("RRSIG verification failed: %v", err)
	}
}

func TestBuildDNSKEYRecord(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := BuildDNSKEYRecord("example.com.", key, dns.AlgECDSAP256, 3600)
	if dk == nil {
		t.Fatal("expected non-nil DNSKEY record")
	}
	if dk.Flags != 256 {
		t.Fatalf("expected flags 256, got %d", dk.Flags)
	}
	if len(dk.PublicKey) != 64 {
		t.Fatalf("expected 64 bytes public key, got %d", len(dk.PublicKey))
	}

	rdata, err := dk.RData()
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, err := dns.ParseDNSKEY(&dns.ResourceRecord{RData: rdata, Type: dns.TypeDNSKEY})
	if err != nil {
		t.Fatal(err)
	}
	if parsedKey.Algorithm != dns.AlgECDSAP256 {
		t.Fatalf("expected algorithm %d, got %d", dns.AlgECDSAP256, parsedKey.Algorithm)
	}
}

func TestCanonicalCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"a.example.com.", "b.example.com.", -1},
		{"b.example.com.", "a.example.com.", 1},
		{"example.com.", "a.example.com.", -1},
		{"example.com.", "example.com.", 0},
		{"z.example.com.", "a.z.example.com.", -1},
	}
	for _, tt := range tests {
		got := canonicalCompare(tt.a, tt.b)
		if (got < 0 && tt.want >= 0) || (got > 0 && tt.want <= 0) || (got == 0 && tt.want != 0) {
			t.Errorf("canonicalCompare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestBuildNSECChain(t *testing.T) {
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.2")},
		&MXRecord{Name: "example.com.", TTLSec: 300, Preference: 10, Host: "mail.example.com."},
	}, nil, nil)

	chain := BuildNSECChain(z)
	if len(chain) == 0 {
		t.Fatal("expected non-empty NSEC chain")
	}
	for _, nsec := range chain {
		if nsec.NextDomain == "" {
			t.Fatal("expected non-empty NextDomain")
		}
		rdata, err := nsec.RData()
		if err != nil {
			t.Fatalf("NSEC RData error: %v", err)
		}
		if len(rdata) < 2 {
			t.Fatalf("NSEC RData too short: %d bytes", len(rdata))
		}
	}
}

func TestAttachDNSSEC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
	}, &DNSSECConfig{
		Enabled:   true,
		Algorithm: dns.AlgECDSAP256,
	}, key)

	req := &dns.Message{
		Header: dns.Header{ID: 42, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: 1},
		},
		Additionals: []dns.ResourceRecord{{
			Name: "", Type: dns.TypeOPT, Class: 1232, TTL: 0x8000,
		}},
	}

	resp := BuildResponse(req, z, "example.com.", dns.TypeA)
	resp = AttachDNSSEC(z, resp, req, key)

	if len(resp.Answers) == 0 {
		t.Fatal("expected answers")
	}
	var hasRRSIG bool
	for _, ans := range resp.Answers {
		if ans.Type == dns.TypeRRSIG {
			hasRRSIG = true
			break
		}
	}
	if !hasRRSIG {
		t.Fatal("expected RRSIG records in signed response")
	}

	var hasDNSKEY bool
	for _, addl := range resp.Additionals {
		if addl.Type == dns.TypeDNSKEY {
			hasDNSKEY = true
			break
		}
	}
	if !hasDNSKEY {
		t.Fatal("expected DNSKEY in additional section")
	}
}

func TestAttachDNSSECNoDOBit(t *testing.T) {
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
	}, &DNSSECConfig{
		Enabled:   true,
		Algorithm: dns.AlgECDSAP256,
	}, nil)

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
	resp = AttachDNSSEC(z, resp, req, nil)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestEcdsaSigToRSSig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("test data"))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	derSig, err := encodeECDSASig(r, s)
	if err != nil {
		t.Fatal(err)
	}
	rsSig := ecdsaSigToRSSig(derSig, dns.AlgECDSAP256)
	if len(rsSig) != 64 {
		t.Fatalf("expected 64 bytes for P-256 signature, got %d", len(rsSig))
	}
}

func encodeECDSASig(r, s *big.Int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	out := make([]byte, len(rBytes)+len(sBytes))
	copy(out, rBytes)
	copy(out[len(rBytes):], sBytes)
	return out, nil
}
