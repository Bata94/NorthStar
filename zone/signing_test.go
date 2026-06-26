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
	}, nil, nil, nil, nil)

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
	}, key, nil, nil)

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
	}, nil, nil, nil)

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

func TestNSEC3HashVector(t *testing.T) {
	// RFC 5155 Appendix A test vectors
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	name := "example."
	hash, err := NSEC3Hash(name, salt, 12)
	if err != nil {
		t.Fatal(err)
	}
	base32 := Base32HexEncode(hash)
	// Expected from RFC 5155 §6.3: 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
	if base32 != "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" {
		t.Errorf("RFC 5155 test vector: got %q, want %q", base32, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")
	}
}

func TestNSEC3HashNoSalt(t *testing.T) {
	// Example with no salt
	hash, err := NSEC3Hash("example.com.", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 20 {
		t.Fatalf("expected 20 bytes (SHA-1), got %d", len(hash))
	}
}

func TestNSEC3HashEmptyName(t *testing.T) {
	hash, err := NSEC3Hash(".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(hash))
	}
}

func TestBase32HexRoundTrip(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	enc := Base32HexEncode(data)
	dec, err := Base32HexDecode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != len(data) {
		t.Fatalf("length mismatch: got %d, want %d", len(dec), len(data))
	}
	for i := range data {
		if dec[i] != data[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, dec[i], data[i])
		}
	}
}

func TestBase32HexInvalidChar(t *testing.T) {
	_, err := Base32HexDecode("0p9mhaveqvm6t7vb!l5lop2u3t2rp3tom")
	if err == nil {
		t.Fatal("expected error for invalid base32hex char")
	}
}

func TestBase32HexEmpty(t *testing.T) {
	enc := Base32HexEncode(nil)
	if enc != "" {
		t.Errorf("expected empty string, got %q", enc)
	}
	dec, err := Base32HexDecode("")
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != 0 {
		t.Fatalf("expected empty bytes, got %d", len(dec))
	}
}

func TestBuildNSEC3Chain(t *testing.T) {
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.2")},
	}, nil, nil, nil, nil)

	chain := BuildNSEC3Chain(z, 0, nil, false)
	if len(chain) == 0 {
		t.Fatal("expected non-empty NSEC3 chain")
	}
	for _, nsec3 := range chain {
		if len(nsec3.NextHashedOwner) == 0 {
			t.Fatal("expected non-empty NextHashedOwner")
		}
		rdata, err := nsec3.RData()
		if err != nil {
			t.Fatalf("NSEC3 RData error: %v", err)
		}
		if len(rdata) < 7 {
			t.Fatalf("NSEC3 RData too short: %d bytes", len(rdata))
		}
		// Verify hash algorithm is 1 (SHA-1)
		if rdata[0] != 1 {
			t.Fatalf("expected hash algorithm 1, got %d", rdata[0])
		}
		// Verify no opt-out flag
		if rdata[1] != 0 {
			t.Fatalf("expected flags 0, got %d", rdata[1])
		}
	}
}

func TestBuildNSEC3ChainWithSalt(t *testing.T) {
	salt := []byte{0xde, 0xad}
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
	}, nil, nil, nil, nil)

	chain := BuildNSEC3Chain(z, 10, salt, false)
	if len(chain) == 0 {
		t.Fatal("expected non-empty NSEC3 chain")
	}
	for _, nsec3 := range chain {
		if len(nsec3.Salt) != 2 || nsec3.Salt[0] != 0xde || nsec3.Salt[1] != 0xad {
			t.Fatalf("expected salt [0xde, 0xad], got %v", nsec3.Salt)
		}
		if nsec3.Iterations != 10 {
			t.Fatalf("expected iterations 10, got %d", nsec3.Iterations)
		}
	}
}

func TestBuildNSEC3ChainWithOptOut(t *testing.T) {
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&NSRecord{Name: "sub.example.com.", TTLSec: 3600, Target: "ns1.sub.example.com."},
	}, nil, nil, nil, nil)

	chain := BuildNSEC3Chain(z, 0, nil, true)
	if len(chain) == 0 {
		t.Fatal("expected non-empty NSEC3 chain")
	}
	// At least one NSEC3 should have the opt-out flag set
	var hasOptOut bool
	for _, nsec3 := range chain {
		if nsec3.Flags&0x01 != 0 {
			hasOptOut = true
			break
		}
	}
	if !hasOptOut {
		t.Fatal("expected opt-out flag set on at least one NSEC3 record")
	}
}

func TestBuildNSEC3ChainEmptyZone(t *testing.T) {
	z := New("empty.zone.", nil, nil, nil, nil, nil)
	chain := BuildNSEC3Chain(z, 0, nil, false)
	if chain != nil {
		t.Fatal("expected nil chain for empty zone")
	}
}

func TestBuildNSEC3ChainOnlyRRSIG(t *testing.T) {
	// RRSIG records should be skipped in NSEC3 type bitmaps
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
		&RRSIGRecord{
			Name: "example.com.", TTLSec: 300,
			TypeCovered: dns.TypeA, Algorithm: 13, Labels: 2, OriginalTTL: 300,
			SigExpiration: 2000000000, SigInception: 1000000000, KeyTag: 12345,
			SignerName: "example.com.", Signature: []byte("fake"),
		},
	}, nil, nil, nil, nil)

	chain := BuildNSEC3Chain(z, 0, nil, false)
	if len(chain) == 0 {
		t.Fatal("expected non-empty NSEC3 chain")
	}
	// Type bitmaps should not include RRSIG
	for _, nsec3 := range chain {
		for _, typ := range nsec3.Types {
			if typ == dns.TypeRRSIG {
				t.Fatal("NSEC3 type bitmap should not include RRSIG")
			}
		}
	}
}

func TestBuildNSEC3PARAMRecord(t *testing.T) {
	z := New("example.com.", []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
	}, nil, nil, nil, nil)

	param := BuildNSEC3PARAMRecord(z, 10, []byte{0xde, 0xad})
	if param == nil {
		t.Fatal("expected non-nil NSEC3PARAM")
	}
	if param.Hash != 1 {
		t.Fatalf("expected hash 1, got %d", param.Hash)
	}
	if param.Iterations != 10 {
		t.Fatalf("expected iterations 10, got %d", param.Iterations)
	}
	if len(param.Salt) != 2 || param.Salt[0] != 0xde || param.Salt[1] != 0xad {
		t.Fatalf("expected salt [0xde, 0xad], got %v", param.Salt)
	}

	rdata, err := param.RData()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := dns.ParseNSEC3PARAM(&dns.ResourceRecord{RData: rdata, Type: dns.TypeNSEC3PARAM})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Iterations != 10 {
		t.Fatalf("round trip iterations: got %d, want 10", parsed.Iterations)
	}
}

func TestAttachDNSSECWithNSEC3(t *testing.T) {
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
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.2")},
	}, &DNSSECConfig{
		Enabled:   true,
		Algorithm: dns.AlgECDSAP256,
		NSEC3:     true,
	}, key, nil, nil)

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
		}
	}

	if !hasRRSIG {
		t.Fatal("expected RRSIG records with NSEC3")
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

func TestAttachDNSSECWithNSEC3NXDOMAIN(t *testing.T) {
	// NSEC3 records should appear in authority for NXDOMAIN responses
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
		NSEC3:     true,
	}, key, nil, nil)

	req := &dns.Message{
		Header: dns.Header{ID: 1, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "nonexistent.example.com.", Type: dns.TypeA, Class: 1},
		},
		Additionals: []dns.ResourceRecord{{
			Name: "", Type: dns.TypeOPT, Class: 1232, TTL: 0x8000,
		}},
	}

	resp := BuildResponse(req, z, "nonexistent.example.com.", dns.TypeA)
	resp = AttachDNSSEC(z, resp, req, key)

	if resp.Header.Flags&0x000F != 3 {
		t.Fatal("expected NXDOMAIN rcode")
	}

	var hasNSEC3, hasNSEC3PARAM bool
	for _, auth := range resp.Authorities {
		if auth.Type == dns.TypeNSEC3 {
			hasNSEC3 = true
		}
	}
	for _, addl := range resp.Additionals {
		if addl.Type == dns.TypeNSEC3PARAM {
			hasNSEC3PARAM = true
		}
	}

	if !hasNSEC3 {
		t.Fatal("expected NSEC3 records in authority for NXDOMAIN")
	}
	if !hasNSEC3PARAM {
		t.Fatal("expected NSEC3PARAM in additional section for NXDOMAIN")
	}
}

func TestAttachDNSSECNSEC3CoveringTypes(t *testing.T) {
	// Verify that NSEC3 type bitmaps include all record types in the zone
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
		&MXRecord{Name: "example.com.", TTLSec: 300, Preference: 10, Host: "mail.example.com."},
		&TXTRecord{Name: "example.com.", TTLSec: 300, Data: "v=spf1 mx -all"},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.2")},
	}, &DNSSECConfig{
		Enabled:   true,
		Algorithm: dns.AlgECDSAP256,
		NSEC3:     true,
	}, key, nil, nil)

	// Query for a non-existent name to trigger NXDOMAIN with NSEC3
	req := &dns.Message{
		Header: dns.Header{ID: 1, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "nonexistent.example.com.", Type: dns.TypeA, Class: 1},
		},
		Additionals: []dns.ResourceRecord{{
			Name: "", Type: dns.TypeOPT, Class: 1232, TTL: 0x8000,
		}},
	}

	resp := BuildResponse(req, z, "nonexistent.example.com.", dns.TypeA)
	resp = AttachDNSSEC(z, resp, req, key)

	var nsec3Count int
	for _, auth := range resp.Authorities {
		if auth.Type == dns.TypeNSEC3 {
			nsec3Count++
		}
	}
	if nsec3Count == 0 {
		t.Fatal("expected NSEC3 records in authority for NXDOMAIN")
	}
}

func TestNSEC3RecordRDataRoundTrip(t *testing.T) {
	// Build an NSEC3 record and verify it can be parsed back
	r := &NSEC3Record{
		Name:            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.com.",
		TTLSec:          3600,
		HashAlgorithm:   1,
		Flags:           0,
		Iterations:      10,
		Salt:            []byte{0xaa, 0xbb, 0xcc, 0xdd},
		NextHashedOwner: []byte("abcdefghij1234567890"),
		Types:           []uint16{1, 15, 16}, // A, MX, TXT
	}

	rdata, err := r.RData()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := dns.ParseNSEC3(&dns.ResourceRecord{RData: rdata, Type: dns.TypeNSEC3})
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}

	if parsed.HashAlgorithm != 1 {
		t.Fatalf("expected HashAlgorithm 1, got %d", parsed.HashAlgorithm)
	}
	if parsed.Flags != 0 {
		t.Fatalf("expected Flags 0, got %d", parsed.Flags)
	}
	if parsed.Iterations != 10 {
		t.Fatalf("expected Iterations 10, got %d", parsed.Iterations)
	}
	if len(parsed.Salt) != 4 {
		t.Fatalf("expected salt len 4, got %d", len(parsed.Salt))
	}
	if len(parsed.NextHashedOwner) == 0 {
		t.Fatal("expected non-empty NextHashedOwner")
	}
	if len(parsed.TypeBitMaps) != 3 {
		t.Fatalf("expected 3 types, got %d", len(parsed.TypeBitMaps))
	}
}

func TestCompareHashes(t *testing.T) {
	tests := []struct {
		a, b []byte
		want int
	}{
		{[]byte{0x01}, []byte{0x02}, -1},
		{[]byte{0x02}, []byte{0x01}, 1},
		{[]byte{0x01, 0x02}, []byte{0x01, 0x01}, 1},
		{[]byte{0x01}, []byte{0x01, 0x00}, -1},
		{[]byte{0x01, 0x00}, []byte{0x01}, 1},
		{[]byte{0x01, 0x02}, []byte{0x01, 0x02}, 0},
		{nil, nil, 0},
	}
	for _, tt := range tests {
		got := compareHashes(tt.a, tt.b)
		if (got < 0 && tt.want >= 0) || (got > 0 && tt.want <= 0) || (got == 0 && tt.want != 0) {
			t.Errorf("compareHashes(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
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
