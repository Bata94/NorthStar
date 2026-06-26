package zone

import (
	"sort"
	"sync"

	"github.com/bata94/northstar/dns"
)

type ZoneHistory struct {
	mu         sync.Mutex
	MaxEntries int
	entries    []struct {
		Serial  uint32
		Records []Record
	}
}

func NewZoneHistory(maxEntries int) *ZoneHistory {
	if maxEntries <= 0 {
		maxEntries = 5
	}
	return &ZoneHistory{MaxEntries: maxEntries}
}

func (h *ZoneHistory) Snapshot(serial uint32, records []Record) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i, e := range h.entries {
		if e.Serial == serial {
			h.entries = append(h.entries[:i], h.entries[i+1:]...)
			break
		}
	}

	cp := make([]Record, len(records))
	copy(cp, records)

	h.entries = append(h.entries, struct {
		Serial  uint32
		Records []Record
	}{Serial: serial, Records: cp})

	sort.Slice(h.entries, func(i, j int) bool {
		return h.entries[i].Serial < h.entries[j].Serial
	})

	for len(h.entries) > h.MaxEntries {
		h.entries = h.entries[1:]
	}
}

func (h *ZoneHistory) Lookup(serial uint32) []Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, e := range h.entries {
		if e.Serial == serial {
			return e.Records
		}
	}
	return nil
}

func (h *ZoneHistory) EarliestSerial() (uint32, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.entries) == 0 {
		return 0, false
	}
	return h.entries[0].Serial, true
}

func (h *ZoneHistory) HasSerial(serial uint32) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, e := range h.entries {
		if e.Serial == serial {
			return true
		}
	}
	return false
}

func (h *ZoneHistory) Copy() *ZoneHistory {
	h.mu.Lock()
	defer h.mu.Unlock()

	nh := NewZoneHistory(h.MaxEntries)
	for _, e := range h.entries {
		cp := make([]Record, len(e.Records))
		copy(cp, e.Records)
		nh.entries = append(nh.entries, struct {
			Serial  uint32
			Records []Record
		}{Serial: e.Serial, Records: cp})
	}
	return nh
}

type recordKey struct {
	name  string
	rtype uint16
	rdata string
}

func recordKeyFromRecord(r Record) recordKey {
	rdata, _ := r.RData()
	return recordKey{
		name:  r.DNSName(),
		rtype: r.DNSType(),
		rdata: string(rdata),
	}
}

func DiffRecords(oldRecords, newRecords []Record) (added, removed []Record) {
	oldSet := make(map[recordKey]Record)
	for _, r := range oldRecords {
		if r.DNSType() == dns.TypeSOA {
			continue
		}
		oldSet[recordKeyFromRecord(r)] = r
	}

	newSet := make(map[recordKey]Record)
	for _, r := range newRecords {
		if r.DNSType() == dns.TypeSOA {
			continue
		}
		newSet[recordKeyFromRecord(r)] = r
	}

	for key, r := range oldSet {
		if _, exists := newSet[key]; !exists {
			removed = append(removed, r)
		}
	}

	for key, r := range newSet {
		if _, exists := oldSet[key]; !exists {
			added = append(added, r)
		}
	}

	sort.Slice(removed, func(i, j int) bool {
		return canonicalCompare(removed[i].DNSName(), removed[j].DNSName()) < 0
	})
	sort.Slice(added, func(i, j int) bool {
		return canonicalCompare(added[i].DNSName(), added[j].DNSName()) < 0
	})

	return
}
