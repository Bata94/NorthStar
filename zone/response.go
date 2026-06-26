package zone

import (
	"encoding/binary"
	"fmt"

	"github.com/bata94/northstar/dns"
)

func BuildResponse(req *dns.Message, zone *Zone, qname string, qtype uint16) *dns.Message {
	records, found := zone.Lookup(qname, qtype)

	maxPayload := extractMaxPayload(req)

	flags := uint16(0x8500) // QR=1, AA=1, RD=1 (copy from req), RA=0 (authoritative)

	var answers, authorities, additionals []dns.ResourceRecord

	if found {
		if qtype == dns.TypeCNAME || qtype == dns.TypeANY {
			for _, r := range records {
				answers = append(answers, recordToRR(r))
			}
		} else {
			// Check for CNAME first
			cnameRecords, hasCNAME := zone.Lookup(qname, dns.TypeCNAME)
			if hasCNAME {
				for _, r := range cnameRecords {
					answers = append(answers, recordToRR(r))
				}
				// Try to follow CNAME for the original type
				if cr, ok := cnameRecords[0].(*CNAMERecord); ok {
					if cnameAnswers, cnameFound := zone.Lookup(cr.Target, qtype); cnameFound {
						for _, r := range cnameAnswers {
							answers = append(answers, recordToRR(r))
						}
					}
				}
			}
			for _, r := range records {
				answers = append(answers, recordToRR(r))
			}
		}
		flags |= 0x0000 // NOERROR
	} else if zone.LooksLikeAuthority(qname) {
		// NODATA - name exists but type doesn't
		flags |= 0x0000 // NOERROR
	} else {
		// NXDOMAIN
		flags |= 0x0003
	}

	// Always include SOA and NS in authority for completeness
	soa := zone.SOA()
	if soa != nil {
		authorities = append(authorities, recordToRR(soa))
	}
	for _, ns := range zone.NS() {
		authorities = append(authorities, recordToRR(ns))
	}

	additionals = append(additionals, dns.ResourceRecord{
		Name:  "",
		Type:  dns.TypeOPT,
		Class: maxPayload,
	})

	return &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: uint16(len(answers)),
			NSCount: uint16(len(authorities)),
			ARCount: uint16(len(additionals)),
		},
		Questions:   req.Questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}
}

func BuildViewResponse(req *dns.Message, zone *Zone, qname string, qtype uint16, viewRecords []Record) *dns.Message {
	maxPayload := extractMaxPayload(req)
	flags := uint16(0x8500)

	var answers, authorities, additionals []dns.ResourceRecord

	if len(viewRecords) > 0 {
		if qtype == dns.TypeCNAME || qtype == dns.TypeANY {
			for _, r := range viewRecords {
				answers = append(answers, recordToRR(r))
			}
		} else {
			cnameRecords, hasCNAME := zone.Lookup(qname, dns.TypeCNAME)
			if hasCNAME {
				for _, r := range cnameRecords {
					answers = append(answers, recordToRR(r))
				}
				if cr, ok := cnameRecords[0].(*CNAMERecord); ok {
					if cnameAnswers, cnameFound := zone.Lookup(cr.Target, qtype); cnameFound {
						for _, r := range cnameAnswers {
							answers = append(answers, recordToRR(r))
						}
					}
				}
			}
			for _, r := range viewRecords {
				answers = append(answers, recordToRR(r))
			}
		}
		flags |= 0x0000
	} else {
		flags |= 0x0003
	}

	soa := zone.SOA()
	if soa != nil {
		authorities = append(authorities, recordToRR(soa))
	}
	for _, ns := range zone.NS() {
		authorities = append(authorities, recordToRR(ns))
	}

	additionals = append(additionals, dns.ResourceRecord{
		Name:  "",
		Type:  dns.TypeOPT,
		Class: maxPayload,
	})

	return &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: uint16(len(answers)),
			NSCount: uint16(len(authorities)),
			ARCount: uint16(len(additionals)),
		},
		Questions:   req.Questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}
}

func BuildNXDOMAIN(req *dns.Message, zone *Zone, qname string) *dns.Message {
	maxPayload := extractMaxPayload(req)

	flags := uint16(0x8503) // QR=1, AA=1, RD=1, RCODE=NXDOMAIN

	var authorities []dns.ResourceRecord
	soa := zone.SOA()
	if soa != nil {
		authorities = append(authorities, recordToRR(soa))
	}

	additionals := []dns.ResourceRecord{{
		Name:  "",
		Type:  dns.TypeOPT,
		Class: maxPayload,
	}}

	return &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: 0,
			NSCount: uint16(len(authorities)),
			ARCount: 1,
		},
		Questions:   req.Questions,
		Authorities: authorities,
		Additionals: additionals,
	}
}

func recordToRR(r Record) dns.ResourceRecord {
	rdata, err := r.RData()
	if err != nil {
		return dns.ResourceRecord{}
	}
	return dns.ResourceRecord{
		Name:     r.DNSName(),
		Type:     r.DNSType(),
		Class:    1,
		TTL:      r.TTL(),
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
}

func BuildRefusedResponse(req *dns.Message) *dns.Message {
	maxPayload := extractMaxPayload(req)
	flags := uint16(0x8005)
	return &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ARCount: 1,
		},
		Questions: req.Questions,
		Additionals: []dns.ResourceRecord{{
			Name:  "",
			Type:  dns.TypeOPT,
			Class: maxPayload,
		}},
	}
}

func extractMaxPayload(req *dns.Message) uint16 {
	for _, rr := range req.Additionals {
		if rr.Type == dns.TypeOPT {
			return rr.Class
		}
	}
	return 512
}

func EncodeName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	var buf []byte
	for _, label := range splitLabels2(name) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	return append(buf, 0)
}

func splitLabels2(name string) []string {
	if name == "" {
		return nil
	}
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

func RRSIGWireForm(rrset []dns.ResourceRecord, rrsigData []byte) ([]byte, error) {
	return buildRRSIGWire(rrset, rrsigData)
}

func buildRRSIGWire(rrset []dns.ResourceRecord, rrsigData []byte) ([]byte, error) {
	if len(rrsigData) < 18 {
		return nil, fmt.Errorf("rrsig data too short: %d bytes", len(rrsigData))
	}
	typeCovered := binary.BigEndian.Uint16(rrsigData[0:2])
	origTTL := binary.BigEndian.Uint32(rrsigData[4:8])
	signerName := extractSignerName(rrsigData)

	var buf []byte
	buf = EncodeName(signerName)
	buf = binary.BigEndian.AppendUint16(buf, typeCovered)
	buf = binary.BigEndian.AppendUint16(buf, 1) // class IN
	buf = binary.BigEndian.AppendUint32(buf, origTTL)
	for _, rr := range rrset {
		buf = canonicalRR(buf, &rr)
	}
	return buf, nil
}

func extractSignerName(data []byte) string {
	if len(data) <= 18 {
		return "."
	}
	off := 18
	if data[off] == 0 {
		return "."
	}
	result := ""
	for off < len(data) {
		if data[off] == 0 {
			break
		}
		labelLen := int(data[off])
		off++
		if off+labelLen > len(data) {
			return "."
		}
		result += string(data[off:off+labelLen]) + "."
		off += labelLen
		if result == "." {
			break
		}
	}
	return result
}

func canonicalRR(buf []byte, rr *dns.ResourceRecord) []byte {
	buf = append(buf, EncodeName(rr.Name)...)
	buf = binary.BigEndian.AppendUint16(buf, rr.Type)
	buf = binary.BigEndian.AppendUint16(buf, rr.Class)
	buf = binary.BigEndian.AppendUint32(buf, rr.TTL)
	buf = binary.BigEndian.AppendUint16(buf, rr.RDLength)
	buf = append(buf, rr.RData...)
	return buf
}
