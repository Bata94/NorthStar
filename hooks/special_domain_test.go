package hooks

import (
	"context"
	"testing"

	"github.com/bata94/northstar/dns"
)

func TestSpecialDomainHookLocalhostA(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	var sent []byte
	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "localhost.", Type: dns.TypeA, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
		Send: func(data []byte) error {
			sent = data
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrHookStop {
		t.Fatalf("expected ErrHookStop, got %v", err)
	}

	var resp dns.Message
	if err := resp.Parse(sent); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Flags&0x000F != dns.RcodeSuccess {
		t.Errorf("expected NOERROR, got RCODE %d", resp.Header.Flags&0x000F)
	}
	if resp.Header.ANCount != 1 {
		t.Fatalf("expected 1 answer, got %d", resp.Header.ANCount)
	}
	if resp.Answers[0].Type != dns.TypeA {
		t.Errorf("expected A record, got type %d", resp.Answers[0].Type)
	}
	if len(resp.Answers[0].RData) != 4 {
		t.Errorf("expected 4-byte RData, got %d", len(resp.Answers[0].RData))
	}
}

func TestSpecialDomainHookLocalhostAAAA(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	var sent []byte
	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "localhost.", Type: dns.TypeAAAA, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
		Send: func(data []byte) error {
			sent = data
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrHookStop {
		t.Fatalf("expected ErrHookStop, got %v", err)
	}

	var resp dns.Message
	if err := resp.Parse(sent); err != nil {
		t.Fatal(err)
	}
	if resp.Header.ANCount != 1 {
		t.Fatalf("expected 1 answer, got %d", resp.Header.ANCount)
	}
	if resp.Answers[0].Type != dns.TypeAAAA {
		t.Errorf("expected AAAA record, got type %d", resp.Answers[0].Type)
	}
}

func TestSpecialDomainHookInvalid(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	var sent []byte
	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "test.invalid.", Type: dns.TypeA, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
		Send: func(data []byte) error {
			sent = data
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrHookStop {
		t.Fatalf("expected ErrHookStop, got %v", err)
	}

	var resp dns.Message
	if err := resp.Parse(sent); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Flags&0x000F != dns.RcodeNXDOMAIN {
		t.Errorf("expected NXDOMAIN, got RCODE %d", resp.Header.Flags&0x000F)
	}
}

func TestSpecialDomainHookTest(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	var sent []byte
	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "something.test.", Type: dns.TypeA, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
		Send: func(data []byte) error {
			sent = data
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrHookStop {
		t.Fatalf("expected ErrHookStop, got %v", err)
	}

	var resp dns.Message
	if err := resp.Parse(sent); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Flags&0x000F != dns.RcodeNXDOMAIN {
		t.Errorf("expected NXDOMAIN, got RCODE %d", resp.Header.Flags&0x000F)
	}
}

func TestSpecialDomainHookExample(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	domains := []string{"example.com.", "www.example.com.", "example.net.", "example.org."}
	for _, d := range domains {
		var sent []byte
		req := &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: d, Type: dns.TypeA, Class: 1}},
		}
		ctx := &Context{
			Ctx:     context.Background(),
			Request: req,
			Send: func(data []byte) error {
				sent = data
				return nil
			},
		}
		if err := hook.Handle(ctx); err != ErrHookStop {
			t.Fatalf("expected ErrHookStop for %s, got %v", d, err)
		}
		var resp dns.Message
		if err := resp.Parse(sent); err != nil {
			t.Fatal(err)
		}
		if resp.Header.Flags&0x000F != dns.RcodeNXDOMAIN {
			t.Errorf("expected NXDOMAIN for %s, got RCODE %d", d, resp.Header.Flags&0x000F)
		}
	}
}

func TestSpecialDomainHookLocal(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	var sent []byte
	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "printer.local.", Type: dns.TypeA, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
		Send: func(data []byte) error {
			sent = data
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrHookStop {
		t.Fatalf("expected ErrHookStop, got %v", err)
	}

	var resp dns.Message
	if err := resp.Parse(sent); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Flags&0x000F != dns.RcodeRefused {
		t.Errorf("expected REFUSED, got RCODE %d", resp.Header.Flags&0x000F)
	}
}

func TestSpecialDomainHookNotSpecial(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "google.com.", Type: dns.TypeA, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
	}

	if err := hook.Handle(ctx); err != nil {
		t.Errorf("expected nil for non-special domain, got %v", err)
	}
}

func TestSpecialDomainHookDisabled(t *testing.T) {
	hook := NewSpecialDomainHook(false, 60)

	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "localhost.", Type: dns.TypeA, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
	}

	if err := hook.Handle(ctx); err != nil {
		t.Errorf("expected nil when disabled, got %v", err)
	}
}

func TestSpecialDomainHookLocalhostANY(t *testing.T) {
	hook := NewSpecialDomainHook(true, 60)

	var sent []byte
	req := &dns.Message{
		Header:    dns.Header{ID: 42, QDCount: 1},
		Questions: []dns.Question{{Name: "localhost.", Type: dns.TypeANY, Class: 1}},
	}
	ctx := &Context{
		Ctx:     context.Background(),
		Request: req,
		Send: func(data []byte) error {
			sent = data
			return nil
		},
	}

	if err := hook.Handle(ctx); err != ErrHookStop {
		t.Fatalf("expected ErrHookStop, got %v", err)
	}

	var resp dns.Message
	if err := resp.Parse(sent); err != nil {
		t.Fatal(err)
	}
	if resp.Header.ANCount != 2 {
		t.Fatalf("expected 2 answers for ANY query, got %d", resp.Header.ANCount)
	}
}
