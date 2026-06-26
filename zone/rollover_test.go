package zone

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testZone(t *testing.T, ksk, zsk *ecdsa.PrivateKey) *Zone {
	t.Helper()
	records := []Record{
		&SOARecord{
			Name:    "example.com.",
			TTLSec:  3600,
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2025010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  86400,
			Minimum: 300,
		},
		&ARecord{Name: "example.com.", TTLSec: 300, IP: net.ParseIP("192.0.2.1")},
	}
	if zsk == nil {
		zsk = ksk
	}
	return New("example.com.", records, &DNSSECConfig{
		Enabled:   true,
		Algorithm: dns.AlgECDSAP256,
		KeyFile:   "",
		ZSKFile:   "",
	}, ksk, zsk, nil)
}

func TestBuildDNSKEYSet(t *testing.T) {
	ksk := testKey(t)
	zsk := testKey(t)
	z := testZone(t, ksk, zsk)

	records, kskTag, zskTag := BuildDNSKEYSet(z, ksk, zsk)
	if len(records) != 2 {
		t.Fatalf("expected 2 DNSKEY records, got %d", len(records))
	}
	kskRec, ok := records[0].(*DNSKEYRecord)
	if !ok {
		t.Fatal("expected *DNSKEYRecord for KSK")
	}
	zskRec, ok := records[1].(*DNSKEYRecord)
	if !ok {
		t.Fatal("expected *DNSKEYRecord for ZSK")
	}
	if kskRec.Flags != 257 {
		t.Errorf("expected KSK flags 257, got %d", kskRec.Flags)
	}
	if zskRec.Flags != 256 {
		t.Errorf("expected ZSK flags 256, got %d", zskRec.Flags)
	}
	if kskTag == 0 {
		t.Error("expected non-zero KSK tag")
	}
	if zskTag == 0 {
		t.Error("expected non-zero ZSK tag")
	}
}

func TestInitZoneRolloverNilConfig(t *testing.T) {
	z := testZone(t, testKey(t), nil)
	rr := InitZoneRollover(z, nil)
	if rr != nil {
		t.Fatal("expected nil rollover for nil config")
	}
}

func TestInitZoneRolloverDisabled(t *testing.T) {
	z := testZone(t, testKey(t), nil)
	rr := InitZoneRollover(z, &config.ZoneRolloverConfig{Enabled: false})
	if rr != nil {
		t.Fatal("expected nil rollover for disabled config")
	}
}

func TestInitZoneRolloverEnabled(t *testing.T) {
	ksk := testKey(t)
	z := testZone(t, ksk, ksk)
	rr := InitZoneRollover(z, &config.ZoneRolloverConfig{Enabled: true, ZSKDays: 30, Overlap: 7, PrePublish: 2})
	if rr == nil {
		t.Fatal("expected non-nil rollover for enabled config")
	}
	defer func() { rr.mu.Lock(); rr.phase = RolloverIdle; rr.mu.Unlock() }()
	if rr.Phase() != RolloverIdle {
		t.Fatalf("expected initial phase Idle, got %v", rr.Phase())
	}
	if z.ZSKKey == ksk {
		t.Fatal("expected ZSKKey to be regenerated when same as SigningKey")
	}
}

func TestInitZoneRolloverAlreadySeparate(t *testing.T) {
	ksk := testKey(t)
	zsk := testKey(t)
	z := testZone(t, ksk, zsk)
	origZSK := z.ZSKKey
	rr := InitZoneRollover(z, &config.ZoneRolloverConfig{Enabled: true, ZSKDays: 30, Overlap: 7, PrePublish: 2})
	if rr == nil {
		t.Fatal("expected non-nil rollover")
	}
	if z.ZSKKey != origZSK {
		t.Fatal("expected ZSKKey unchanged when already separate from KSK")
	}
}

func TestRolloverPhaseAccessors(t *testing.T) {
	ksk := testKey(t)
	zsk := testKey(t)
	z := testZone(t, ksk, zsk)

	rr := &ZoneRollover{
		zone:      z,
		oldZSK:    zsk,
		oldTag:    42,
		newZSK:    testKey(t),
		newTag:    99,
		phase:     RolloverPublishing,
		startTime: time.Now(),
	}

	if rr.Phase() != RolloverPublishing {
		t.Fatalf("expected Publishing phase")
	}
	if rr.OldZSK() == nil {
		t.Fatal("expected non-nil OldZSK during Publishing")
	}
	if rr.NewZSK() == nil {
		t.Fatal("expected non-nil NewZSK during Publishing")
	}
	if rr.OldZSKTag() != 42 {
		t.Fatalf("expected OldZSKTag 42, got %d", rr.OldZSKTag())
	}
	if rr.NewZSKTag() != 99 {
		t.Fatalf("expected NewZSKTag 99, got %d", rr.NewZSKTag())
	}
	if rr.SigningKey() != rr.oldZSK {
		t.Fatal("expected SigningKey to be oldZSK during Publishing")
	}
	if rr.SigningTag() != 42 {
		t.Fatalf("expected SigningTag 42, got %d", rr.SigningTag())
	}
	oldRec := rr.OldDNSKEYRecord()
	if oldRec == nil {
		t.Fatal("expected non-nil OldDNSKEYRecord during Publishing")
	}
	if oldRec.Flags != 256 {
		t.Fatalf("expected OldDNSKEYRecord flags 256, got %d", oldRec.Flags)
	}
}

func TestRolloverPhaseActive(t *testing.T) {
	ksk := testKey(t)
	newZSK := testKey(t)
	oldZSK := testKey(t)
	z := testZone(t, ksk, newZSK)
	z.ZSKKey = newZSK

	rr := &ZoneRollover{
		zone:      z,
		oldZSK:    oldZSK,
		oldTag:    42,
		newZSK:    newZSK,
		newTag:    99,
		phase:     RolloverActive,
		startTime: time.Now(),
	}

	if rr.Phase() != RolloverActive {
		t.Fatalf("expected Active phase")
	}
	if rr.OldZSK() != oldZSK {
		t.Fatal("expected OldZSK to return old key during Active")
	}
	if rr.NewZSK() != newZSK {
		t.Fatal("expected NewZSK to return new key during Active")
	}
	if rr.SigningKey() != newZSK {
		t.Fatal("expected SigningKey to be zone.ZSKKey during Active")
	}
	if rr.SigningTag() != 99 {
		t.Fatalf("expected SigningTag 99 during Active, got %d", rr.SigningTag())
	}
	oldRec := rr.OldDNSKEYRecord()
	if oldRec == nil {
		t.Fatal("expected non-nil OldDNSKEYRecord during Active")
	}
}

func TestRolloverPhaseCleanup(t *testing.T) {
	ksk := testKey(t)
	newZSK := testKey(t)
	z := testZone(t, ksk, newZSK)

	rr := &ZoneRollover{
		zone:      z,
		oldZSK:    nil,
		oldTag:    0,
		newZSK:    newZSK,
		newTag:    99,
		phase:     RolloverCleanup,
		startTime: time.Now(),
	}

	if rr.OldZSK() != nil {
		t.Fatal("expected nil OldZSK during Cleanup")
	}
	if rr.NewZSK() != nil {
		t.Fatal("expected nil NewZSK during Cleanup")
	}
	if rr.SigningKey() != newZSK {
		t.Fatal("expected SigningKey to be zone.ZSKKey during Cleanup")
	}
	if rr.OldDNSKEYRecord() != nil {
		t.Fatal("expected nil OldDNSKEYRecord during Cleanup")
	}
}

func TestRolloverPhaseIdle(t *testing.T) {
	ksk := testKey(t)
	zsk := testKey(t)
	z := testZone(t, ksk, zsk)

	rr := &ZoneRollover{
		zone:      z,
		phase:     RolloverIdle,
		startTime: time.Now(),
	}

	if rr.OldZSK() != nil {
		t.Fatal("expected nil OldZSK during Idle")
	}
	if rr.NewZSK() != nil {
		t.Fatal("expected nil NewZSK during Idle")
	}
	if rr.SigningKey() != zsk {
		t.Fatal("expected SigningKey to be zone.ZSKKey during Idle")
	}
	zskTag := zskKeyTag(z)
	if rr.SigningTag() != zskTag {
		t.Fatalf("expected SigningTag %d during Idle, got %d", zskTag, rr.SigningTag())
	}
}

func TestRolloverAttachDNSSECWithPublishingPhase(t *testing.T) {
	ksk := testKey(t)
	newZSK := testKey(t)
	oldZSK := testKey(t)
	z := testZone(t, ksk, oldZSK)
	z.ZSKKey = oldZSK

	rr := &ZoneRollover{
		zone:      z,
		oldZSK:    oldZSK,
		oldTag:    zskKeyTag(z),
		newZSK:    newZSK,
		newTag:    computeZSKTag(newZSK, z),
		phase:     RolloverPublishing,
		startTime: time.Now(),
	}
	z.Rollover = rr

	req := &dns.Message{
		Header: dns.Header{ID: 1, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: 1},
		},
		Additionals: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeOPT, Class: 4096, TTL: 0x8000},
		},
	}
	resp := buildBasicResponse(z, req)
	resp = AttachDNSSEC(z, resp, req, ksk)

	if len(resp.Additionals) == 0 {
		t.Fatal("expected additional records with DNSSEC records")
	}

	var dnskeyCount int
	for _, rr := range resp.Additionals {
		if rr.Type == dns.TypeDNSKEY {
			dnskeyCount++
		}
	}
	if dnskeyCount != 3 {
		t.Fatalf("expected 3 DNSKEY records (KSK + old ZSK + new ZSK) during Publishing, got %d", dnskeyCount)
	}

	var rrsigCount int
	for _, rr := range resp.Additionals {
		if rr.Type == dns.TypeRRSIG {
			rrsigCount++
		}
	}
	if rrsigCount < 1 {
		t.Fatalf("expected at least 1 RRSIG for DNSKEY in additional, got %d", rrsigCount)
	}

	anRRSIGs := 0
	for _, rr := range resp.Answers {
		if rr.Type == dns.TypeRRSIG {
			anRRSIGs++
		}
	}
	if anRRSIGs < 1 {
		t.Errorf("expected at least 1 RRSIG in answer section, got %d", anRRSIGs)
	}
}

func TestRolloverAttachDNSSECWithActivePhase(t *testing.T) {
	ksk := testKey(t)
	newZSK := testKey(t)
	oldZSK := testKey(t)
	z := testZone(t, ksk, newZSK)
	z.ZSKKey = newZSK

	rr := &ZoneRollover{
		zone:      z,
		oldZSK:    oldZSK,
		oldTag:    computeZSKTag(oldZSK, z),
		newZSK:    newZSK,
		newTag:    zskKeyTag(z),
		phase:     RolloverActive,
		startTime: time.Now(),
	}
	z.Rollover = rr

	req := &dns.Message{
		Header: dns.Header{ID: 1, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: 1},
		},
		Additionals: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeOPT, Class: 4096, TTL: 0x8000},
		},
	}
	resp := buildBasicResponse(z, req)
	resp = AttachDNSSEC(z, resp, req, ksk)

	var dnskeyCount int
	for _, rr := range resp.Additionals {
		if rr.Type == dns.TypeDNSKEY {
			dnskeyCount++
		}
	}
	if dnskeyCount != 3 {
		t.Fatalf("expected 3 DNSKEY records (KSK + new ZSK + old ZSK) during Active, got %d", dnskeyCount)
	}
}

func TestRolloverAttachDNSSECWithCleanupPhase(t *testing.T) {
	ksk := testKey(t)
	newZSK := testKey(t)
	z := testZone(t, ksk, newZSK)
	z.ZSKKey = newZSK

	rr := &ZoneRollover{
		zone:      z,
		oldZSK:    nil,
		oldTag:    0,
		newZSK:    newZSK,
		newTag:    zskKeyTag(z),
		phase:     RolloverCleanup,
		startTime: time.Now(),
	}
	z.Rollover = rr

	req := &dns.Message{
		Header: dns.Header{ID: 1, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: 1},
		},
		Additionals: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeOPT, Class: 4096, TTL: 0x8000},
		},
	}
	resp := buildBasicResponse(z, req)
	resp = AttachDNSSEC(z, resp, req, ksk)

	var dnskeyCount int
	for _, rr := range resp.Additionals {
		if rr.Type == dns.TypeDNSKEY {
			dnskeyCount++
		}
	}
	if dnskeyCount != 2 {
		t.Fatalf("expected 2 DNSKEY records (KSK + ZSK) during Cleanup, got %d", dnskeyCount)
	}
}

func buildBasicResponse(z *Zone, req *dns.Message) *dns.Message {
	soa := findSOARecords(z)
	resp := &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   0x8580,
			QDCount: 1,
			ANCount: 1,
		},
		Questions: req.Questions,
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeA, Class: 1, TTL: 300, RDLength: 4, RData: net.ParseIP("192.0.2.1").To4()},
		},
	}
	if len(soa) > 0 {
		resp.Header.NSCount = 1
		rdata, _ := soa[0].RData()
		resp.Authorities = []dns.ResourceRecord{
			{Name: soa[0].DNSName(), Type: soa[0].DNSType(), Class: 1, TTL: soa[0].TTL(), RDLength: uint16(len(rdata)), RData: rdata},
		}
	}
	resp.Additionals = req.Additionals
	resp.Header.ARCount = uint16(len(resp.Additionals))
	return resp
}
