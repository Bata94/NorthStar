package zone

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/bata94/northstar/dns"
)

func newTestZone() *Zone {
	records := []Record{
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("93.184.216.34")},
		&AAAARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")},
		&CNAMERecord{Name: "alias.example.com.", TTLSec: 600, Target: "www.example.com."},
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 20250101, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&NSRecord{Name: "example.com.", TTLSec: 86400, Target: "ns1.example.com."},
		&MXRecord{Name: "example.com.", TTLSec: 3600, Preference: 10, Host: "mail.example.com."},
		&TXTRecord{Name: "example.com.", TTLSec: 3600, Data: "v=spf1 mx ~all"},
	}
	return New("example.com.", records, nil, nil, nil, nil)
}

func newAXFRRequest(zoneName string) *dns.Message {
	return &dns.Message{
		Header: dns.Header{ID: 42, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: zoneName, Type: dns.TypeAXFR, Class: 1},
		},
	}
}

func TestBuildAXFRMessagesBasic(t *testing.T) {
	z := newTestZone()
	req := newAXFRRequest("example.com.")

	msgs := BuildAXFRMessages(z, req)
	if msgs == nil {
		t.Fatal("BuildAXFRMessages returned nil")
	}

	if len(msgs) < 3 {
		t.Fatalf("expected at least 3 messages (SOA + records + SOA), got %d", len(msgs))
	}

	firstMsg := msgs[0]
	if firstMsg.Header.QDCount != 1 {
		t.Errorf("first message QDCount: got %d, want 1", firstMsg.Header.QDCount)
	}
	if firstMsg.Header.ANCount != 1 {
		t.Errorf("first message ANCount: got %d, want 1", firstMsg.Header.ANCount)
	}
	if firstMsg.Header.ID != 42 {
		t.Errorf("first message ID: got %d, want 42", firstMsg.Header.ID)
	}
	if len(firstMsg.Answers) != 1 {
		t.Fatalf("expected 1 answer in first message, got %d", len(firstMsg.Answers))
	}
	if firstMsg.Answers[0].Type != dns.TypeSOA {
		t.Errorf("first message should be SOA, got type %d", firstMsg.Answers[0].Type)
	}

	lastMsg := msgs[len(msgs)-1]
	if len(lastMsg.Answers) != 1 {
		t.Fatalf("expected 1 answer in last message, got %d", len(lastMsg.Answers))
	}
	if lastMsg.Answers[0].Type != dns.TypeSOA {
		t.Errorf("last message should be SOA, got type %d", lastMsg.Answers[0].Type)
	}

	middleMsgs := msgs[1 : len(msgs)-1]
	if len(middleMsgs) != 6 {
		t.Fatalf("expected 6 middle messages (A, AAAA, CNAME, NS, MX, TXT), got %d", len(middleMsgs))
	}

	typeCounts := make(map[uint16]int)
	for _, m := range middleMsgs {
		if len(m.Answers) == 1 {
			typeCounts[m.Answers[0].Type]++
		}
	}
	if typeCounts[dns.TypeA] != 1 {
		t.Errorf("expected 1 A record, got %d", typeCounts[dns.TypeA])
	}
	if typeCounts[dns.TypeAAAA] != 1 {
		t.Errorf("expected 1 AAAA record, got %d", typeCounts[dns.TypeAAAA])
	}
	if typeCounts[dns.TypeCNAME] != 1 {
		t.Errorf("expected 1 CNAME record, got %d", typeCounts[dns.TypeCNAME])
	}
	if typeCounts[dns.TypeNS] != 1 {
		t.Errorf("expected 1 NS record, got %d", typeCounts[dns.TypeNS])
	}
	if typeCounts[dns.TypeMX] != 1 {
		t.Errorf("expected 1 MX record, got %d", typeCounts[dns.TypeMX])
	}
	if typeCounts[dns.TypeTXT] != 1 {
		t.Errorf("expected 1 TXT record, got %d", typeCounts[dns.TypeTXT])
	}
}

func TestBuildAXFRMessagesEmptyZone(t *testing.T) {
	zone := New("empty.zone.", nil, nil, nil, nil, nil)
	req := newAXFRRequest("empty.zone.")

	msgs := BuildAXFRMessages(zone, req)
	if msgs != nil {
		t.Errorf("expected nil for zone with no SOA, got %d messages", len(msgs))
	}
}

func TestBuildAXFRMessagesCanonicalOrder(t *testing.T) {
	records := []Record{
		&ARecord{Name: "zzz.example.com.", TTLSec: 300, IP: net.ParseIP("10.0.0.3")},
		&ARecord{Name: "aaa.example.com.", TTLSec: 300, IP: net.ParseIP("10.0.0.1")},
		&ARecord{Name: "mmm.example.com.", TTLSec: 300, IP: net.ParseIP("10.0.0.2")},
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
	}
	z := New("example.com.", records, nil, nil, nil, nil)
	req := newAXFRRequest("example.com.")

	msgs := BuildAXFRMessages(z, req)
	if msgs == nil {
		t.Fatal("BuildAXFRMessages returned nil")
	}

	middleMsgs := msgs[1 : len(msgs)-1]

	if len(middleMsgs) != 3 {
		t.Fatalf("expected 3 middle messages, got %d", len(middleMsgs))
	}

	got := make([]string, len(middleMsgs))
	for i, m := range middleMsgs {
		if len(m.Answers) > 0 {
			got[i] = m.Answers[0].Name
		}
	}
	if got[0] != "aaa.example.com." {
		t.Errorf("first in canonical order: got %q, want %q", got[0], "aaa.example.com.")
	}
	if got[1] != "mmm.example.com." {
		t.Errorf("second in canonical order: got %q, want %q", got[1], "mmm.example.com.")
	}
	if got[2] != "zzz.example.com." {
		t.Errorf("third in canonical order: got %q, want %q", got[2], "zzz.example.com.")
	}
}

func TestBuildAXFRMessagesRoundTrip(t *testing.T) {
	z := newTestZone()
	req := newAXFRRequest("example.com.")

	msgs := BuildAXFRMessages(z, req)
	if msgs == nil {
		t.Fatal("BuildAXFRMessages returned nil")
	}

	for i, m := range msgs {
		packed := m.Pack()
		var parsed dns.Message
		if err := parsed.Parse(packed); err != nil {
			t.Fatalf("message %d failed to parse: %v", i, err)
		}
		if parsed.Header.ID != 42 {
			t.Errorf("message %d ID: got %d, want 42", i, parsed.Header.ID)
		}
		if len(parsed.Questions) != 1 {
			t.Errorf("message %d questions: got %d, want 1", i, len(parsed.Questions))
		}
		if len(parsed.Answers) != 1 {
			t.Errorf("message %d answers: got %d, want 1", i, len(parsed.Answers))
		}
	}
}

func TestBuildAXFRMessagesSOASameFirstLast(t *testing.T) {
	z := newTestZone()
	req := newAXFRRequest("example.com.")

	msgs := BuildAXFRMessages(z, req)
	if msgs == nil {
		t.Fatal("BuildAXFRMessages returned nil")
	}

	if len(msgs) < 2 {
		t.Fatal("need at least 2 messages for SOA comparison")
	}

	first := msgs[0]
	last := msgs[len(msgs)-1]

	if len(first.Answers) != 1 || len(last.Answers) != 1 {
		t.Fatal("expected single answer in first/last messages")
	}

	if string(first.Answers[0].RData) != string(last.Answers[0].RData) {
		t.Error("first and last SOA RData differ")
	}

	if first.Answers[0].TTL != last.Answers[0].TTL {
		t.Errorf("first SOA TTL %d != last SOA TTL %d", first.Answers[0].TTL, last.Answers[0].TTL)
	}
}

func buildSOARDATA(mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	rdata := encodeName(mname)
	rdata = append(rdata, encodeName(rname)...)
	rdata = binary.BigEndian.AppendUint32(rdata, serial)
	rdata = binary.BigEndian.AppendUint32(rdata, refresh)
	rdata = binary.BigEndian.AppendUint32(rdata, retry)
	rdata = binary.BigEndian.AppendUint32(rdata, expire)
	rdata = binary.BigEndian.AppendUint32(rdata, minimum)
	return rdata
}

func newIXFRRequest(zoneName string, clientSerial uint32) *dns.Message {
	soaRdata := buildSOARDATA("ns1.example.com.", "admin.example.com.", clientSerial, 3600, 900, 86400, 3600)
	return &dns.Message{
		Header: dns.Header{ID: 42, Flags: 0x0100, QDCount: 1, NSCount: 1},
		Questions: []dns.Question{
			{Name: zoneName, Type: dns.TypeIXFR, Class: 1},
		},
		Authorities: []dns.ResourceRecord{{
			Name:     zoneName,
			Type:     dns.TypeSOA,
			Class:    1,
			TTL:      3600,
			RDLength: uint16(len(soaRdata)),
			RData:    soaRdata,
		}},
	}
}

func TestBuildIXFRMessagesSameSerial(t *testing.T) {
	z := newTestZone()
	req := newIXFRRequest("example.com.", 20250101)

	msgs, doAXFR := BuildIXFRMessages(z, req)
	if doAXFR {
		t.Fatal("expected no AXFR fallback for matching serial")
	}
	if msgs == nil {
		t.Fatal("BuildIXFRMessages returned nil")
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (SOA), got %d", len(msgs))
	}
	if msgs[0].Answers[0].Type != dns.TypeSOA {
		t.Error("expected SOA in response")
	}
}

func TestBuildIXFRMessagesWithHistory(t *testing.T) {
	currentRecords := []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 20250101, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("93.184.216.34")},
		&NSRecord{Name: "example.com.", TTLSec: 86400, Target: "ns1.example.com."},
	}
	z := New("example.com.", currentRecords, nil, nil, nil, nil)

	oldRecords := []Record{
		&SOARecord{
			Name: "example.com.", TTLSec: 3600,
			MName: "ns1.example.com.", RName: "admin.example.com.",
			Serial: 20250100, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("93.184.216.34")},
		&ARecord{Name: "old.example.com.", TTLSec: 300, IP: net.ParseIP("10.0.0.1")},
		&NSRecord{Name: "example.com.", TTLSec: 86400, Target: "ns1.example.com."},
	}
	history := NewZoneHistory(5)
	history.Snapshot(20250100, oldRecords)
	z.History = history

	req := newIXFRRequest("example.com.", 20250100)

	msgs, doAXFR := BuildIXFRMessages(z, req)
	if doAXFR {
		t.Fatal("expected no AXFR fallback for history serial")
	}
	if msgs == nil {
		t.Fatal("BuildIXFRMessages returned nil")
	}

	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (SOA + removed + SOA), got %d", len(msgs))
	}

	if msgs[0].Answers[0].Type != dns.TypeSOA {
		t.Error("message 0 should be SOA")
	}
	if msgs[1].Answers[0].Name != "old.example.com." {
		t.Errorf("message 1 should be removed A record for old.example.com., got %q", msgs[1].Answers[0].Name)
	}
	if msgs[2].Answers[0].Type != dns.TypeSOA {
		t.Error("message 2 should be SOA")
	}
}

func TestBuildIXFRMessagesAddedAndRemoved(t *testing.T) {
	oldRecords := []Record{
		&ARecord{Name: "removed.example.com.", TTLSec: 300, IP: net.ParseIP("10.0.0.1")},
		&SOARecord{
			Name: "zone.example.com.", TTLSec: 3600,
			MName: "ns1.zone.example.com.", RName: "admin.zone.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
	}

	currentRecords := []Record{
		&ARecord{Name: "added.example.com.", TTLSec: 300, IP: net.ParseIP("10.0.0.2")},
		&SOARecord{
			Name: "zone.example.com.", TTLSec: 3600,
			MName: "ns1.zone.example.com.", RName: "admin.zone.example.com.",
			Serial: 2, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
	}

	z := New("zone.example.com.", currentRecords, nil, nil, nil, nil)
	history := NewZoneHistory(5)
	history.Snapshot(1, oldRecords)
	z.History = history

	req := newIXFRRequest("zone.example.com.", 1)

	msgs, doAXFR := BuildIXFRMessages(z, req)
	if doAXFR {
		t.Fatal("expected no AXFR fallback")
	}
	if msgs == nil {
		t.Fatal("BuildIXFRMessages returned nil")
	}

	if len(msgs) != 4 {
		t.Fatalf("expected 4 messages (SOA + removed + SOA + added), got %d", len(msgs))
	}

	if msgs[0].Answers[0].Type != dns.TypeSOA {
		t.Error("message 0 should be SOA")
	}
	if msgs[1].Answers[0].Name != "removed.example.com." {
		t.Errorf("message 1 should be removed record, got %q", msgs[1].Answers[0].Name)
	}
	if msgs[2].Answers[0].Type != dns.TypeSOA {
		t.Error("message 2 should be SOA")
	}
	if msgs[3].Answers[0].Name != "added.example.com." {
		t.Errorf("message 3 should be added record, got %q", msgs[3].Answers[0].Name)
	}
}

func TestBuildIXFRMessagesFallbackToAXFR(t *testing.T) {
	z := newTestZone()
	req := newIXFRRequest("example.com.", 99999999)

	msgs, doAXFR := BuildIXFRMessages(z, req)
	if !doAXFR {
		t.Fatal("expected AXFR fallback for unknown serial")
	}
	if msgs != nil {
		t.Fatalf("expected nil messages for fallback, got %d", len(msgs))
	}
}

func TestBuildIXFRMessagesNoSOAInRequest(t *testing.T) {
	z := newTestZone()

	req := &dns.Message{
		Header: dns.Header{ID: 42, Flags: 0x0100, QDCount: 1},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeIXFR, Class: 1},
		},
	}

	msgs, doAXFR := BuildIXFRMessages(z, req)
	if doAXFR {
		t.Fatal("expected no AXFR fallback when no SOA in request")
	}
	if msgs != nil {
		t.Fatalf("expected nil messages, got %d", len(msgs))
	}
}

func TestBuildIXFRMessagesNoHistory(t *testing.T) {
	z := newTestZone()
	req := newIXFRRequest("example.com.", 20250100)

	msgs, doAXFR := BuildIXFRMessages(z, req)
	if !doAXFR {
		t.Fatal("expected AXFR fallback when no history available")
	}
	if msgs != nil {
		t.Fatalf("expected nil messages for fallback, got %d", len(msgs))
	}
}

func TestBuildIXFRMessagesEmptyZone(t *testing.T) {
	z := New("empty.zone.", nil, nil, nil, nil, nil)
	req := newIXFRRequest("empty.zone.", 1)

	msgs, doAXFR := BuildIXFRMessages(z, req)
	if doAXFR {
		t.Error("expected no AXFR fallback for empty zone")
	}
	if msgs != nil {
		t.Errorf("expected nil for empty zone, got %d messages", len(msgs))
	}
}

func TestZoneHistorySnapshotAndLookup(t *testing.T) {
	h := NewZoneHistory(3)

	snapRecords := []Record{
		&ARecord{Name: "test.example.com.", TTLSec: 300, IP: net.ParseIP("1.2.3.4")},
	}

	h.Snapshot(100, snapRecords)

	got := h.Lookup(100)
	if got == nil {
		t.Fatal("expected to find serial 100")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}

	got2 := h.Lookup(999)
	if got2 != nil {
		t.Fatal("expected nil for unknown serial")
	}

	if !h.HasSerial(100) {
		t.Error("HasSerial(100) should be true")
	}
	if h.HasSerial(999) {
		t.Error("HasSerial(999) should be false")
	}
}

func TestZoneHistoryMaxEntries(t *testing.T) {
	h := NewZoneHistory(2)

	h.Snapshot(1, []Record{
		&SOARecord{Name: "z.", TTLSec: 3600, MName: "ns.z.", RName: "admin.z.", Serial: 1},
	})
	h.Snapshot(2, []Record{
		&SOARecord{Name: "z.", TTLSec: 3600, MName: "ns.z.", RName: "admin.z.", Serial: 2},
	})
	h.Snapshot(3, []Record{
		&SOARecord{Name: "z.", TTLSec: 3600, MName: "ns.z.", RName: "admin.z.", Serial: 3},
	})

	if h.HasSerial(1) {
		t.Error("serial 1 should be evicted")
	}
	if !h.HasSerial(2) {
		t.Error("serial 2 should exist")
	}
	if !h.HasSerial(3) {
		t.Error("serial 3 should exist")
	}
}

func TestZoneHistoryEarliestSerial(t *testing.T) {
	h := NewZoneHistory(3)

	_, ok := h.EarliestSerial()
	if ok {
		t.Error("expected no earliest serial for empty history")
	}

	h.Snapshot(100, nil)
	serial, ok := h.EarliestSerial()
	if !ok || serial != 100 {
		t.Errorf("expected earliest serial 100, got %d", serial)
	}

	h.Snapshot(50, nil)
	serial, ok = h.EarliestSerial()
	if !ok || serial != 50 {
		t.Errorf("expected earliest serial 50, got %d", serial)
	}
}

func TestDiffRecordsAddedOnly(t *testing.T) {
	oldRecords := []Record{
		&SOARecord{Name: "example.com.", TTLSec: 3600, MName: "ns.", RName: "admin.", Serial: 1},
	}
	newRecords := []Record{
		&SOARecord{Name: "example.com.", TTLSec: 3600, MName: "ns.", RName: "admin.", Serial: 1},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("1.2.3.4")},
	}

	added, removed := DiffRecords(oldRecords, newRecords)
	if len(added) != 1 {
		t.Errorf("expected 1 added, got %d", len(added))
	}
	if len(removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(removed))
	}
}

func TestDiffRecordsRemovedOnly(t *testing.T) {
	oldRecords := []Record{
		&SOARecord{Name: "example.com.", TTLSec: 3600, MName: "ns.", RName: "admin.", Serial: 1},
		&ARecord{Name: "old.example.com.", TTLSec: 300, IP: net.ParseIP("1.2.3.4")},
	}
	newRecords := []Record{
		&SOARecord{Name: "example.com.", TTLSec: 3600, MName: "ns.", RName: "admin.", Serial: 1},
	}

	added, removed := DiffRecords(oldRecords, newRecords)
	if len(added) != 0 {
		t.Errorf("expected 0 added, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(removed))
	}
}

func TestDiffRecordsBoth(t *testing.T) {
	oldRecords := []Record{
		&SOARecord{Name: "example.com.", TTLSec: 3600, MName: "ns.", RName: "admin.", Serial: 1},
		&ARecord{Name: "old.example.com.", TTLSec: 300, IP: net.ParseIP("1.2.3.4")},
	}
	newRecords := []Record{
		&SOARecord{Name: "example.com.", TTLSec: 3600, MName: "ns.", RName: "admin.", Serial: 2},
		&ARecord{Name: "new.example.com.", TTLSec: 300, IP: net.ParseIP("5.6.7.8")},
	}

	added, removed := DiffRecords(oldRecords, newRecords)
	if len(added) != 1 {
		t.Errorf("expected 1 added, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(removed))
	}
}

func TestDiffRecordsNoChanges(t *testing.T) {
	records := []Record{
		&SOARecord{Name: "example.com.", TTLSec: 3600, MName: "ns.", RName: "admin.", Serial: 1},
		&ARecord{Name: "www.example.com.", TTLSec: 300, IP: net.ParseIP("1.2.3.4")},
	}

	added, removed := DiffRecords(records, records)
	if len(added) != 0 {
		t.Errorf("expected 0 added, got %d", len(added))
	}
	if len(removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(removed))
	}
}

func TestBuildIXFRMessagesSingleRecordZone(t *testing.T) {
	records := []Record{
		&SOARecord{
			Name: "single.example.com.", TTLSec: 3600,
			MName: "ns1.single.example.com.", RName: "admin.single.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 86400, Minimum: 3600,
		},
	}
	z := New("single.example.com.", records, nil, nil, nil, nil)
	req := newAXFRRequest("single.example.com.")

	msgs := BuildAXFRMessages(z, req)
	if msgs == nil {
		t.Fatal("BuildAXFRMessages returned nil")
	}

	if len(msgs) != 2 {
		t.Fatalf("expected exactly 2 messages (SOA + SOA), got %d", len(msgs))
	}

	for i, m := range msgs {
		if len(m.Answers) != 1 || m.Answers[0].Type != dns.TypeSOA {
			t.Errorf("message %d should be SOA", i)
		}
	}
}
