// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package hooks

import (
	"log/slog"

	"github.com/bata94/northstar/dns"
)

type AnyQueryHook struct {
	enabled  bool
	priority int
	action   string
}

func NewAnyQueryHook(enabled bool, priority int, action string) *AnyQueryHook {
	return &AnyQueryHook{
		enabled:  enabled,
		priority: priority,
		action:   action,
	}
}

func (h *AnyQueryHook) Name() string {
	return "any_query"
}

func (h *AnyQueryHook) Lifecycle() Lifecycle {
	return PreResolve
}

func (h *AnyQueryHook) Priority() int {
	return h.priority
}

func (h *AnyQueryHook) Enabled() bool {
	return h.enabled
}

func (h *AnyQueryHook) Handle(ctx *Context) error {
	if !h.enabled || h.action != "minimal" {
		return nil
	}

	q := ctx.Request.Questions[0]
	if q.Type != dns.TypeANY {
		return nil
	}

	slog.Warn("ANY query handled with minimal response", "domain", q.Name)

	maxPayload := uint16(512)
	for _, rr := range ctx.Request.Additionals {
		if rr.Type == dns.TypeOPT {
			maxPayload = rr.Class
			break
		}
	}

	cpu := "ANY"
	os := "."
	rdata := make([]byte, 0, 1+len(cpu)+1+len(os))
	rdata = append(rdata, byte(len(cpu)))
	rdata = append(rdata, cpu...)
	rdata = append(rdata, byte(len(os)))
	rdata = append(rdata, os...)

	resp := dns.Message{
		Header: dns.Header{
			ID:      ctx.Request.Header.ID,
			Flags:   0x8000 | 0x0080,
			QDCount: 1,
			ANCount: 1,
			ARCount: 1,
		},
		Questions: ctx.Request.Questions,
		Answers: []dns.ResourceRecord{{
			Name:     q.Name,
			Type:     dns.TypeHINFO,
			Class:    1,
			TTL:      0,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		}},
		Additionals: []dns.ResourceRecord{{
			Name:  "",
			Type:  dns.TypeOPT,
			Class: maxPayload,
		}},
	}
	packed := resp.Pack()
	if err := ctx.Send(packed); err != nil {
		slog.Error("Error sending ANY minimal response", "error", err)
	}

	return ErrHookStop
}
