package zone

import (
	"errors"
	"sort"

	"github.com/bata94/northstar/dns"
)

func BuildIXFRMessages(zone *Zone, req *dns.Message) ([]*dns.Message, bool) {
	soa := zone.SOA()
	if soa == nil {
		return nil, false
	}

	clientSerial, err := extractIXFRSerial(req)
	if err != nil {
		return nil, false
	}

	currentSerial := soa.Serial

	if clientSerial == currentSerial {
		msg := buildAXFRMessage(req, 0x8500, soa)
		msg.Header.ANCount = 1
		return []*dns.Message{msg}, false
	}

	var oldRecords []Record
	if zone.History != nil {
		oldRecords = zone.History.Lookup(clientSerial)
	}

	if oldRecords == nil {
		return nil, true
	}

	added, removed := DiffRecords(oldRecords, zone.Records)

	var msgs []*dns.Message
	flags := uint16(0x8500)

	msgs = append(msgs, buildAXFRMessage(req, flags, soa))

	for _, r := range removed {
		msgs = append(msgs, buildAXFRRecordMessage(req, flags, r))
	}

	msgs = append(msgs, buildAXFRMessage(req, flags, soa))

	for _, r := range added {
		msgs = append(msgs, buildAXFRRecordMessage(req, flags, r))
	}

	return msgs, false
}

func extractIXFRSerial(req *dns.Message) (uint32, error) {
	for _, rr := range req.Authorities {
		if rr.Type == dns.TypeSOA {
			return dns.ParseSOASerial(&rr)
		}
	}
	return 0, errors.New("zone: no SOA in IXFR request authority section")
}

func BuildAXFRMessages(zone *Zone, req *dns.Message) []*dns.Message {
	soa := zone.SOA()
	if soa == nil {
		return nil
	}

	var names []string
	for name := range zone.byName {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return canonicalCompare(names[i], names[j]) < 0
	})

	var msgs []*dns.Message

	flags := uint16(0x8500)

	msgs = append(msgs, buildAXFRMessage(req, flags, soa))

	for _, name := range names {
		for _, r := range zone.byName[name] {
			if r.DNSType() == dns.TypeSOA {
				continue
			}
			msgs = append(msgs, buildAXFRRecordMessage(req, flags, r))
		}
	}

	msgs = append(msgs, buildAXFRMessage(req, flags, soa))

	return msgs
}

func buildAXFRMessage(req *dns.Message, flags uint16, soa *SOARecord) *dns.Message {
	rdata, _ := soa.RData()
	return &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: 1,
		},
		Questions: req.Questions,
		Answers: []dns.ResourceRecord{{
			Name:     soa.DNSName(),
			Type:     soa.DNSType(),
			Class:    1,
			TTL:      soa.TTL(),
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		}},
	}
}

func buildAXFRRecordMessage(req *dns.Message, flags uint16, r Record) *dns.Message {
	rdata, err := r.RData()
	if err != nil {
		return nil
	}
	return &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: 1,
		},
		Questions: req.Questions,
		Answers: []dns.ResourceRecord{{
			Name:     r.DNSName(),
			Type:     r.DNSType(),
			Class:    1,
			TTL:      r.TTL(),
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		}},
	}
}
