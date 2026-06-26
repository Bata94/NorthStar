package dns

import (
	"os"
	"testing"
	"time"
)

func TestTrustAnchorStoreAddInitial(t *testing.T) {
	s := NewTrustAnchorStore(0, 0)
	s.AddInitial(DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	if !s.IsTrusted(DNSKEYKeyTag(".", []byte("test-public-key-32-bytes-long!"), 13)) {
		t.Fatal("expected initial key to be trusted")
	}
}

func TestTrustAnchorStoreObserveNew(t *testing.T) {
	s := NewTrustAnchorStore(time.Hour, time.Hour)
	trusted := s.Observe(DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	if trusted {
		t.Fatal("expected new key to NOT be trusted immediately")
	}
	keyTag := DNSKEYKeyTag(".", []byte("test-public-key-32-bytes-long!"), 13)
	if s.IsTrusted(keyTag) {
		t.Fatal("expected new key not to be trusted during add hold-down")
	}
}

func TestTrustAnchorStoreAddHoldDown(t *testing.T) {
	s := NewTrustAnchorStore(0, 0)
	s.Observe(DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	keyTag := DNSKEYKeyTag(".", []byte("test-public-key-32-bytes-long!"), 13)
	if s.IsTrusted(keyTag) {
		t.Fatal("expected still not trusted - hold-down not elapsed")
	}
}

func TestTrustAnchorStoreAddHoldDownElapsed(t *testing.T) {
	s := NewTrustAnchorStore(-1, 0)
	s.Observe(DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	keyTag := DNSKEYKeyTag(".", []byte("test-public-key-32-bytes-long!"), 13)
	s.Tick()
	if !s.IsTrusted(keyTag) {
		t.Fatal("expected key to be trusted after add hold-down elapsed")
	}
}

func TestTrustAnchorStoreObserveRevocation(t *testing.T) {
	s := NewTrustAnchorStore(0, time.Hour)
	s.AddInitial(DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	keyTag := DNSKEYKeyTag(".", []byte("test-public-key-32-bytes-long!"), 13)
	s.Observe(DNSKEY{
		Flags: 256 | 0x0080, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	if s.IsTrusted(keyTag) {
		t.Fatal("expected revoked key not to be trusted")
	}
}

func TestTrustAnchorStoreRevokeAndRemove(t *testing.T) {
	s := NewTrustAnchorStore(0, -1)
	s.AddInitial(DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	keyTag := DNSKEYKeyTag(".", []byte("test-public-key-32-bytes-long!"), 13)
	s.Observe(DNSKEY{
		Flags: 256 | 0x0080, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}, ".")
	s.Tick()
	if s.IsTrusted(keyTag) {
		t.Fatal("expected removed key not to be trusted")
	}
}

func TestTrustAnchorStoreGetValid(t *testing.T) {
	s := NewTrustAnchorStore(0, 0)
	s.AddInitial(DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("key1-32-bytes-for-testing-!!!!!!"),
	}, ".")
	valid := s.GetValid()
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(valid))
	}
}

func TestParseTrustAnchorFile(t *testing.T) {
	content := `; trust anchor file
. 3600 IN DNSKEY 257 3 13 ( 
    QvbxkqvOoRol3W6iBOHXobEoR4k8FgPM9WEd1G7hW00= )
`
	f, err := os.CreateTemp(t.TempDir(), "trust-anchor.*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseTrustAnchorFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one entry")
	}
	if entries[0].Owner != "." {
		t.Fatalf("expected owner '.', got %q", entries[0].Owner)
	}
	if entries[0].DNSKEY.Flags != 257 {
		t.Fatalf("expected flags 257 (KSK), got %d", entries[0].DNSKEY.Flags)
	}
}

func TestParseTrustAnchorFileEmpty(t *testing.T) {
	content := "# empty file\n"
	f, err := os.CreateTemp(t.TempDir(), "trust-anchor.*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	_, err = ParseTrustAnchorFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChainWithStore(t *testing.T) {
	s := NewTrustAnchorStore(0, 0)
	dnskey := DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}
	owner := "."
	s.AddInitial(dnskey, owner)
	if !VerifyChain(s, nil, &dnskey, owner) {
		t.Fatal("expected trusted key to verify chain")
	}
}

func TestVerifyChainUntrusted(t *testing.T) {
	s := NewTrustAnchorStore(0, 0)
	dnskey := DNSKEY{
		Flags: 256, Protocol: 3, Algorithm: 13,
		PublicKey: []byte("test-public-key-32-bytes-long!"),
	}
	if VerifyChain(s, nil, &dnskey, ".") {
		t.Fatal("expected untrusted key to fail chain verification")
	}
}
