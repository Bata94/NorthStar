package hooks

import (
	"testing"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
)

func TestQMinimizerPreResolve(t *testing.T) {
	hpre, _ := NewQMinimizerHooks(true, 300, 301, 2)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"already short", "example.com", "example.com"},
		{"subdomain", "a.b.c.example.com", "example.com"},
		{"many labels", "x.y.z.example.co.uk", "co.uk"},
		{"single label", "localhost", "localhost"},
		{"trailing dot", "a.b.example.com.", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &dns.Message{
				Questions: []dns.Question{{Name: tt.input, Type: 1, Class: 1}},
			}
			ctx := &Context{Request: req}

			if err := hpre.Handle(ctx); err != nil {
				t.Fatal(err)
			}
			if req.Questions[0].Name != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, req.Questions[0].Name)
			}
		})
	}
}

func TestQMinimizerPrePostRoundTrip(t *testing.T) {
	hpre, hpost := NewQMinimizerHooks(true, 300, 301, 2)

	req := &dns.Message{
		Questions: []dns.Question{{Name: "deep.sub.example.com", Type: 1, Class: 1}},
	}
	entry := &cache.Entry{
		Domain: "deep.sub.example.com",
		Answers: []dns.ResourceRecord{{
			Name:  "deep.sub.example.com",
			Type:  1,
			Class: 1,
			TTL:   60,
			RData: []byte{127, 0, 0, 1},
		}},
	}

	ctx := &Context{
		Request: req,
		Entry:   entry,
	}

	if err := hpre.Handle(ctx); err != nil {
		t.Fatal(err)
	}
	if req.Questions[0].Name != "example.com" {
		t.Fatalf("expected minimized to example.com, got %s", req.Questions[0].Name)
	}

	if err := hpost.Handle(ctx); err != nil {
		t.Fatal(err)
	}
	if req.Questions[0].Name != "deep.sub.example.com" {
		t.Fatalf("expected restored to deep.sub.example.com, got %s", req.Questions[0].Name)
	}
	if entry.Answers[0].Name != "deep.sub.example.com" {
		t.Fatalf("expected answer name restored to deep.sub.example.com, got %s", entry.Answers[0].Name)
	}
}

func TestQMinimizerDisabled(t *testing.T) {
	hpre, hpost := NewQMinimizerHooks(false, 300, 301, 2)

	if hpre.Enabled() {
		t.Fatal("expected disabled")
	}
	if hpost.Enabled() {
		t.Fatal("expected disabled")
	}
}

func TestQMinimizerPreservesCustomLabels(t *testing.T) {
	hpre, _ := NewQMinimizerHooks(true, 300, 301, 3)

	req := &dns.Message{
		Questions: []dns.Question{{Name: "a.b.c.example.com", Type: 1, Class: 1}},
	}
	ctx := &Context{Request: req}

	if err := hpre.Handle(ctx); err != nil {
		t.Fatal(err)
	}
	if req.Questions[0].Name != "c.example.com" {
		t.Fatalf("expected c.example.com with keep=3, got %s", req.Questions[0].Name)
	}
}

func TestQMinimizerNoQuestions(t *testing.T) {
	hpre, _ := NewQMinimizerHooks(true, 300, 301, 2)

	req := &dns.Message{}
	ctx := &Context{Request: req}

	if err := hpre.Handle(ctx); err != nil {
		t.Fatal(err)
	}
}
