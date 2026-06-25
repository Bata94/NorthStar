// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

func mustPack(t *testing.T, m *Message) []byte {
	t.Helper()
	data := m.Pack()
	if len(data) < 12 {
		t.Fatal("pack produced short message")
	}
	return data
}

func mustParse(t *testing.T, data []byte) *Message {
	t.Helper()
	var m Message
	if err := m.Parse(data); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &m
}

func roundTrip(t *testing.T, m *Message) {
	t.Helper()
	data := mustPack(t, m)
	parsed := mustParse(t, data)

	if parsed.Header.ID != m.Header.ID {
		t.Errorf("ID: got %d, want %d", parsed.Header.ID, m.Header.ID)
	}
	if parsed.Header.Flags != m.Header.Flags {
		t.Errorf("Flags: got %d, want %d", parsed.Header.Flags, m.Header.Flags)
	}
	if parsed.Header.QDCount != m.Header.QDCount {
		t.Errorf("QDCount: got %d, want %d", parsed.Header.QDCount, m.Header.QDCount)
	}
	if parsed.Header.ANCount != m.Header.ANCount {
		t.Errorf("ANCount: got %d, want %d", parsed.Header.ANCount, m.Header.ANCount)
	}

	for i, q := range m.Questions {
		if parsed.Questions[i].Name != q.Name {
			t.Errorf("Q[%d] Name: got %s, want %s", i, parsed.Questions[i].Name, q.Name)
		}
		if parsed.Questions[i].Type != q.Type {
			t.Errorf("Q[%d] Type: got %d, want %d", i, parsed.Questions[i].Type, q.Type)
		}
		if parsed.Questions[i].Class != q.Class {
			t.Errorf("Q[%d] Class: got %d, want %d", i, parsed.Questions[i].Class, q.Class)
		}
	}

	for i, rr := range m.Answers {
		if parsed.Answers[i].Name != rr.Name {
			t.Errorf("A[%d] Name: got %s, want %s", i, parsed.Answers[i].Name, rr.Name)
		}
		if parsed.Answers[i].Type != rr.Type {
			t.Errorf("A[%d] Type: got %d, want %d", i, parsed.Answers[i].Type, rr.Type)
		}
		if parsed.Answers[i].Class != rr.Class {
			t.Errorf("A[%d] Class: got %d, want %d", i, parsed.Answers[i].Class, rr.Class)
		}
		if parsed.Answers[i].RDLength != rr.RDLength {
			t.Errorf("A[%d] RDLength: got %d, want %d", i, parsed.Answers[i].RDLength, rr.RDLength)
		}
	}
}

func TestRoundTripA(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1234, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "example.com", Type: 1, Class: 1}},
		Answers: []ResourceRecord{{
			Name: "example.com", Type: 1, Class: 1, TTL: 300,
			RDLength: 4, RData: net.ParseIP("1.2.3.4").To4(),
		}},
	}
	roundTrip(t, m)
}

func TestRoundTripAAAA(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 5678, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "ipv6.example", Type: 28, Class: 1}},
		Answers: []ResourceRecord{{
			Name: "ipv6.example", Type: 28, Class: 1, TTL: 600,
			RDLength: 16, RData: net.ParseIP("2001:db8::1").To16(),
		}},
	}
	roundTrip(t, m)
}

func TestRoundTripCNAME(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 2},
		Questions: []Question{{Name: "www.example.com", Type: 1, Class: 1}},
		Answers: []ResourceRecord{
			{Name: "www.example.com", Type: 5, Class: 1, TTL: 300,
				RDLength: 17, RData: []byte{3, 'f', 'o', 'o', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
			{Name: "foo.example.com", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()},
		},
	}
	roundTrip(t, m)
}

func TestRoundTripNS(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 42, Flags: 0x8180, QDCount: 1, ANCount: 0, NSCount: 2},
		Questions: []Question{{Name: "example.com", Type: 2, Class: 1}},
		Authorities: []ResourceRecord{
			{Name: "example.com", Type: 2, Class: 1, TTL: 86400,
				RDLength: 6, RData: []byte{2, 'n', 's', 1, 'a', 0}},
			{Name: "example.com", Type: 2, Class: 1, TTL: 86400,
				RDLength: 6, RData: []byte{2, 'n', 's', 1, 'b', 0}},
		},
	}
	roundTrip(t, m)
}

func TestRoundTripSOA(t *testing.T) {
	rdata := []byte{
		2, 'n', 's', 1, 'a', 0,
		3, 'a', 'd', 'm', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
		0, 0, 0, 0x3C, 0, 0, 0x0E, 0x10, 0, 0x00, 0x09, 0x3A, 0x80, 0, 0x00, 0x01, 0x51, 0x80,
	}
	m := &Message{
		Header:    Header{ID: 99, Flags: 0x8180, QDCount: 1, NSCount: 1},
		Questions: []Question{{Name: "example.com", Type: 6, Class: 1}},
		Authorities: []ResourceRecord{{
			Name: "example.com", Type: 6, Class: 1, TTL: 3600,
			RDLength: uint16(len(rdata)), RData: rdata,
		}},
	}
	roundTrip(t, m)
}

func TestRoundTripOPT(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 7, Flags: 0x0100, QDCount: 1, ARCount: 1},
		Questions: []Question{{Name: "example.com", Type: 1, Class: 1}},
		Additionals: []ResourceRecord{{
			Name: "", Type: TypeOPT, Class: 4096,
			TTL: 0, RDLength: 0,
		}},
	}
	roundTrip(t, m)
}

func TestRootName(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, Flags: 0x0100, QDCount: 1},
		Questions: []Question{{Name: "", Type: 1, Class: 1}},
	}
	roundTrip(t, m)
}

func TestNameCompression(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 2},
		Questions: []Question{{Name: "example.com", Type: 1, Class: 1}},
		Answers: []ResourceRecord{
			{Name: "example.com", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("1.2.3.4").To4()},
			{Name: "sub.example.com", Type: 1, Class: 1, TTL: 300,
				RDLength: 4, RData: net.ParseIP("5.6.7.8").To4()},
		},
	}
	roundTrip(t, m)

	if len(mustPack(t, m)) < len(mustPack(t, &Message{
		Header:    Header{ID: 1, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "example.com", Type: 1, Class: 1}},
		Answers: []ResourceRecord{{
			Name: "sub.example.com", Type: 1, Class: 1, TTL: 300,
			RDLength: 4, RData: net.ParseIP("5.6.7.8").To4(),
		}},
	})) {
		t.Error("expected compression to reduce size for repeated suffix")
	}
}

func TestCompressionLoop(t *testing.T) {
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[4:6], 1)
	data[12] = 0xC0
	data[13] = 0x0C
	var m Message
	err := m.Parse(data)
	if err == nil {
		t.Fatal("expected compression loop error")
	}
}

func TestTruncatedPacket(t *testing.T) {
	var m Message
	err := m.Parse([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for truncated packet")
	}
}

func TestTruncatedName(t *testing.T) {
	data := make([]byte, 12+2)
	binary.BigEndian.PutUint16(data[4:6], 1)
	data[12] = 0x0A
	data[13] = 0x00
	var m Message
	err := m.Parse(data)
	if err == nil {
		t.Fatal("expected error for truncated name (label longer than remaining data)")
	}
}

func TestTruncatedQuestion(t *testing.T) {
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[4:6], 1)
	data[12] = 0
	var m Message
	err := m.Parse(data)
	if err == nil {
		t.Fatal("expected error for truncated question (missing type/class)")
	}
}

func TestTruncatedRR(t *testing.T) {
	data := make([]byte, 12+1+10)
	binary.BigEndian.PutUint16(data[6:8], 1)
	data[12] = 0
	binary.BigEndian.PutUint16(data[21:23], 100)
	var m Message
	err := m.Parse(data)
	if err == nil {
		t.Fatal("expected error for truncated RR")
	}
}

func TestARoundTrip(t *testing.T) {
	ip := net.ParseIP("192.0.2.1").To4()
	rr := ResourceRecord{Name: "test.example", Type: 1, Class: 1, TTL: 1234, RDLength: 4, RData: ip}
	got := rr.A()
	if !got.Equal(ip) {
		t.Errorf("A() = %s, want %s", got, ip)
	}
	if rr.AAAA() != nil {
		t.Error("AAAA() on A record should return nil")
	}
}

func TestAAAARoundTrip(t *testing.T) {
	ip := net.ParseIP("2001:db8::2").To16()
	rr := ResourceRecord{Name: "test.example", Type: 28, Class: 1, TTL: 5678, RDLength: 16, RData: ip}
	got := rr.AAAA()
	if !got.Equal(ip) {
		t.Errorf("AAAA() = %s, want %s", got, ip)
	}
	if rr.A() != nil {
		t.Error("A() on AAAA record should return nil")
	}
}

func TestQuestionString(t *testing.T) {
	m := &Message{
		Header:    Header{QDCount: 1},
		Questions: []Question{{Name: "example.com"}},
	}
	if m.Question() != "example.com" {
		t.Errorf("Question() = %s, want example.com", m.Question())
	}
	empty := &Message{}
	if empty.Question() != "" {
		t.Errorf("Question() = %s, want empty", empty.Question())
	}
}

func TestMultipleQuestions(t *testing.T) {
	m := &Message{
		Header: Header{ID: 1, Flags: 0x0100, QDCount: 2},
		Questions: []Question{
			{Name: "example.com", Type: 1, Class: 1},
			{Name: "example.org", Type: 28, Class: 1},
		},
	}
	roundTrip(t, m)
}
