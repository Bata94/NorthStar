// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package hooks

import (
	"context"
	"testing"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
)

func TestNewPipeline(t *testing.T) {
	p := NewPipeline()
	if p == nil {
		t.Fatal("expected non-nil pipeline")
	}
}

func TestPipelineRegisterAndRunEmpty(t *testing.T) {
	p := NewPipeline()
	ctx := &Context{Ctx: context.Background()}

	if err := p.Run(PreResolve, ctx); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if err := p.Run(PostResolve, ctx); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if err := p.Run(PreResponse, ctx); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if err := p.Run(PostResponse, ctx); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestRateLimitHook(t *testing.T) {
	mem := cache.NewMemory(0, nil)
	defer mem.Close()

	m := metrics.New()

	hook := NewRateLimitHook(5, "servfail", 100, true, false)
	p := NewPipeline()
	p.Register(hook)

	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "example.com", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.1",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send:     func(_ []byte) error { return nil },
	}

	// First 5 calls should pass
	for i := 0; i < 5; i++ {
		if err := p.Run(PreResolve, ctx); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}

	// 6th call should be rate limited
	if err := p.Run(PreResolve, ctx); err != ErrRateLimited {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}
}

func TestRateLimitHookDropAction(t *testing.T) {
	mem := cache.NewMemory(0, nil)
	defer mem.Close()

	m := metrics.New()

	hook := NewRateLimitHook(1, "drop", 100, true, false)
	p := NewPipeline()
	p.Register(hook)

	sendCalled := false
	ctx := &Context{
		Ctx: context.Background(),
		Request: &dns.Message{
			Header:    dns.Header{ID: 42, QDCount: 1},
			Questions: []dns.Question{{Name: "example.com", Type: 1, Class: 1}},
		},
		ClientIP: "10.0.0.2",
		Network:  "udp",
		Cache:    mem,
		Metrics:  m,
		Send: func(_ []byte) error {
			sendCalled = true
			return nil
		},
	}

	// First call passes
	if err := p.Run(PreResolve, ctx); err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}

	// Second call exceeds rate, should NOT call Send with "drop" action
	if err := p.Run(PreResolve, ctx); err != ErrRateLimited {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}
	if sendCalled {
		t.Error("Send should not be called with 'drop' action")
	}
}

func TestDisabledHook(t *testing.T) {
	hook := NewRateLimitHook(5, "servfail", 100, false, false)
	if hook.Enabled() {
		t.Error("disabled hook should not be enabled")
	}
}

func TestRateLimitZeroRate(t *testing.T) {
	hook := NewRateLimitHook(0, "servfail", 100, true, false)
	if hook.Enabled() {
		t.Error("zero-rate hook should not be enabled")
	}
}

func TestPipelineReset(t *testing.T) {
	p := NewPipeline()
	hook := NewRateLimitHook(5, "servfail", 100, true, false)
	p.Register(hook)

	p.Reset()

	ctx := &Context{Ctx: context.Background()}
	if err := p.Run(PreResolve, ctx); err != nil {
		t.Errorf("after reset, expected nil, got %v", err)
	}
}

func TestHookPriority(t *testing.T) {
	var order []string
	p := NewPipeline()

	low := &testHook{name: "low", priority: 10, lifecycle: PreResolve, enabled: true, handler: func(ctx *Context) error {
		order = append(order, "low")
		return nil
	}}
	high := &testHook{name: "high", priority: 5, lifecycle: PreResolve, enabled: true, handler: func(ctx *Context) error {
		order = append(order, "high")
		return nil
	}}

	p.Register(low)
	p.Register(high)

	ctx := &Context{Ctx: context.Background()}
	_ = p.Run(PreResolve, ctx)

	if len(order) != 2 || order[0] != "high" || order[1] != "low" {
		t.Errorf("expected [high low], got %v", order)
	}
}

type testHook struct {
	name      string
	lifecycle Lifecycle
	priority  int
	enabled   bool
	handler   func(ctx *Context) error
}

func (h *testHook) Name() string              { return h.name }
func (h *testHook) Lifecycle() Lifecycle      { return h.lifecycle }
func (h *testHook) Priority() int             { return h.priority }
func (h *testHook) Enabled() bool             { return h.enabled }
func (h *testHook) Handle(ctx *Context) error { return h.handler(ctx) }
