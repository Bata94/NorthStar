// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

func (m *Message) Question() string {
	if len(m.Questions) > 0 {
		return m.Questions[0].Name
	}
	return ""
}

func (r *ResourceRecord) A() net.IP {
	if r.Type == 1 && len(r.RData) == 4 {
		return net.IP(r.RData)
	}
	return nil
}

func (r *ResourceRecord) AAAA() net.IP {
	if r.Type == 28 && len(r.RData) == 16 {
		return net.IP(r.RData)
	}
	return nil
}

func readName(data []byte, off int, visited map[int]bool) (string, int, error) {
	var labels []string
	for {
		if off >= len(data) {
			return "", off, errors.New("dns: truncated name")
		}
		b := data[off]
		if b == 0 {
			off++
			return strings.Join(labels, "."), off, nil
		}
		if b&0xC0 == 0xC0 {
			if off+1 >= len(data) {
				return "", off, errors.New("dns: truncated pointer")
			}
			ptr := int(b&0x3F)<<8 | int(data[off+1])
			if visited[ptr] {
				return "", off, errors.New("dns: compression loop")
			}
			visited[ptr] = true
			suffix, _, err := readName(data, ptr, visited)
			if err != nil {
				return "", off, err
			}
			labels = append(labels, suffix)
			off += 2
			return strings.Join(labels, "."), off, nil
		}
		length := int(b)
		off++
		if off+length > len(data) {
			return "", off, errors.New("dns: truncated label")
		}
		labels = append(labels, string(data[off:off+length]))
		off += length
	}
}

func writeName(buf *[]byte, name string, comp map[string]uint16) {
	if name == "" {
		*buf = append(*buf, 0)
		return
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		suffix := strings.Join(labels[i:], ".")
		if offset, ok := comp[suffix]; ok {
			*buf = append(*buf, byte(0xC0|offset>>8), byte(offset))
			return
		}
		comp[suffix] = uint16(len(*buf))
		*buf = append(*buf, byte(len(label)))
		*buf = append(*buf, label...)
	}
	*buf = append(*buf, 0)
}

func (m *Message) Parse(data []byte) error {
	if len(data) < 12 {
		return errors.New("dns: packet too short")
	}

	m.Header.ID = binary.BigEndian.Uint16(data[0:2])
	m.Header.Flags = binary.BigEndian.Uint16(data[2:4])
	m.Header.QDCount = binary.BigEndian.Uint16(data[4:6])
	m.Header.ANCount = binary.BigEndian.Uint16(data[6:8])
	m.Header.NSCount = binary.BigEndian.Uint16(data[8:10])
	m.Header.ARCount = binary.BigEndian.Uint16(data[10:12])

	off := 12

	for range m.Header.QDCount {
		var q Question
		var err error
		q.Name, off, err = readName(data, off, map[int]bool{})
		if err != nil {
			return err
		}
		if off+4 > len(data) {
			return errors.New("dns: truncated question")
		}
		q.Type = binary.BigEndian.Uint16(data[off : off+2])
		q.Class = binary.BigEndian.Uint16(data[off+2 : off+4])
		off += 4
		m.Questions = append(m.Questions, q)
	}

	for range m.Header.ANCount {
		var rr ResourceRecord
		var err error
		rr.Name, off, err = readName(data, off, map[int]bool{})
		if err != nil {
			return err
		}
		if off+10 > len(data) {
			return errors.New("dns: truncated RR")
		}
		rr.Type = binary.BigEndian.Uint16(data[off : off+2])
		rr.Class = binary.BigEndian.Uint16(data[off+2 : off+4])
		rr.TTL = binary.BigEndian.Uint32(data[off+4 : off+8])
		rr.RDLength = binary.BigEndian.Uint16(data[off+8 : off+10])
		off += 10
		if off+int(rr.RDLength) > len(data) {
			return errors.New("dns: truncated RData")
		}
		rr.RData = make([]byte, rr.RDLength)
		copy(rr.RData, data[off:off+int(rr.RDLength)])
		off += int(rr.RDLength)
		m.Answers = append(m.Answers, rr)
	}

	for range m.Header.NSCount {
		var rr ResourceRecord
		var err error
		rr.Name, off, err = readName(data, off, map[int]bool{})
		if err != nil {
			return err
		}
		if off+10 > len(data) {
			return errors.New("dns: truncated RR")
		}
		rr.Type = binary.BigEndian.Uint16(data[off : off+2])
		rr.Class = binary.BigEndian.Uint16(data[off+2 : off+4])
		rr.TTL = binary.BigEndian.Uint32(data[off+4 : off+8])
		rr.RDLength = binary.BigEndian.Uint16(data[off+8 : off+10])
		off += 10
		if off+int(rr.RDLength) > len(data) {
			return errors.New("dns: truncated RData")
		}
		rr.RData = make([]byte, rr.RDLength)
		copy(rr.RData, data[off:off+int(rr.RDLength)])
		off += int(rr.RDLength)
		m.Authorities = append(m.Authorities, rr)
	}

	for range m.Header.ARCount {
		var rr ResourceRecord
		var err error
		rr.Name, off, err = readName(data, off, map[int]bool{})
		if err != nil {
			return err
		}
		if off+10 > len(data) {
			return errors.New("dns: truncated RR")
		}
		rr.Type = binary.BigEndian.Uint16(data[off : off+2])
		rr.Class = binary.BigEndian.Uint16(data[off+2 : off+4])
		rr.TTL = binary.BigEndian.Uint32(data[off+4 : off+8])
		rr.RDLength = binary.BigEndian.Uint16(data[off+8 : off+10])
		off += 10
		if off+int(rr.RDLength) > len(data) {
			return errors.New("dns: truncated RData")
		}
		rr.RData = make([]byte, rr.RDLength)
		copy(rr.RData, data[off:off+int(rr.RDLength)])
		off += int(rr.RDLength)
		m.Additionals = append(m.Additionals, rr)
	}

	return nil
}

func (m *Message) Pack() []byte {
	buf := make([]byte, 0, 512)

	buf = binary.BigEndian.AppendUint16(buf, m.Header.ID)
	buf = binary.BigEndian.AppendUint16(buf, m.Header.Flags)
	buf = binary.BigEndian.AppendUint16(buf, m.Header.QDCount)
	buf = binary.BigEndian.AppendUint16(buf, m.Header.ANCount)
	buf = binary.BigEndian.AppendUint16(buf, m.Header.NSCount)
	buf = binary.BigEndian.AppendUint16(buf, m.Header.ARCount)

	comp := map[string]uint16{}

	for _, q := range m.Questions {
		writeName(&buf, q.Name, comp)
		buf = binary.BigEndian.AppendUint16(buf, q.Type)
		buf = binary.BigEndian.AppendUint16(buf, q.Class)
	}

	writeRRs := func(rrs []ResourceRecord) {
		for _, rr := range rrs {
			writeName(&buf, rr.Name, comp)
			buf = binary.BigEndian.AppendUint16(buf, rr.Type)
			buf = binary.BigEndian.AppendUint16(buf, rr.Class)
			buf = binary.BigEndian.AppendUint32(buf, rr.TTL)
			buf = binary.BigEndian.AppendUint16(buf, rr.RDLength)
			buf = append(buf, rr.RData...)
		}
	}

	writeRRs(m.Answers)
	writeRRs(m.Authorities)
	writeRRs(m.Additionals)

	return buf
}
