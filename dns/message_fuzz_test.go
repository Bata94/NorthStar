package dns

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzParseMessage(f *testing.F) {
	seeds := []struct {
		name string
		data []byte
	}{
		{"valid A query", buildRawQuery("example.com.", TypeA, 1)},
		{"valid AAAA query", buildRawQuery("google.com.", TypeAAAA, 1)},
		{"valid MX query", buildRawQuery("example.com.", TypeMX, 1)},
		{"valid response", buildRawResponse("example.com.", TypeA, 1)},
		{"empty packet", []byte{}},
		{"header only", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"large garbage", bytes.Repeat([]byte{0xFF}, 65535)},
	}
	for _, s := range seeds {
		f.Add(s.data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var m Message
		err := m.Parse(data)
		if err != nil {
			return
		}
		packed := m.Pack()
		var m2 Message
		if err := m2.Parse(packed); err != nil {
			t.Errorf("round-trip failed: %v", err)
		}
		if len(m.Questions) != len(m2.Questions) {
			t.Errorf("question count mismatch: %d vs %d", len(m.Questions), len(m2.Questions))
		}
		if len(m.Answers) != len(m2.Answers) {
			t.Errorf("answer count mismatch: %d vs %d", len(m.Answers), len(m2.Answers))
		}
	})
}

func FuzzCompressionPointers(f *testing.F) {
	seeds := [][]byte{
		{},
		{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1},
		buildRawQuery("a.b.c.example.com.", TypeA, 1),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var m Message
		err := m.Parse(data)
		if err == nil {
			_ = m.Pack()
		}
	})
}

func FuzzWriteReadName(f *testing.F) {
	names := []string{
		"",
		".",
		"example.com.",
		"a.b.c.d.e.example.com.",
		"localhost.",
		strings.Repeat("a.", 63) + "com.",
	}
	for _, n := range names {
		f.Add(n)
	}

	f.Fuzz(func(t *testing.T, name string) {
		comp := map[string]uint16{}
		var data []byte
		writeName(&data, name, comp)
		if _, _, err := readName(data, 0, map[int]bool{}); err != nil {
			return
		}
	})
}

func buildRawQuery(name string, qtype, qclass uint16) []byte {
	m := Message{
		Header:    Header{ID: 1, Flags: 0x0100, QDCount: 1},
		Questions: []Question{{Name: name, Type: qtype, Class: qclass}},
	}
	return m.Pack()
}

func buildRawResponse(name string, qtype, qclass uint16) []byte {
	m := Message{
		Header:    Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: name, Type: qtype, Class: qclass}},
		Answers: []ResourceRecord{{
			Name: name, Type: qtype, Class: qclass,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
	}
	return m.Pack()
}
