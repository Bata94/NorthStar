// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package hooks

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/bata94/northstar/dns"
	"github.com/prometheus/client_golang/prometheus"
)

type RateLimitHook struct {
	Rate      int
	Action    string
	FailClose bool
	priority  int
	enabled   bool
}

func NewRateLimitHook(rate int, action string, priority int, enabled bool, failClose bool) *RateLimitHook {
	return &RateLimitHook{
		Rate:      rate,
		Action:    action,
		FailClose: failClose,
		priority:  priority,
		enabled:   enabled,
	}
}

func (h *RateLimitHook) Name() string         { return "rate_limiting" }
func (h *RateLimitHook) Lifecycle() Lifecycle { return PreResolve }
func (h *RateLimitHook) Priority() int        { return h.priority }
func (h *RateLimitHook) Enabled() bool        { return h.enabled && h.Rate > 0 }

func (h *RateLimitHook) Handle(ctx *Context) error {
	key := fmt.Sprintf("northstar:ratelimit:%s:%d", ctx.ClientIP, time.Now().Unix())
	val, err := ctx.Cache.Incr(ctx.Ctx, key, time.Second)
	if err != nil {
		slog.Error("Rate limit cache error", "error", err)
		if h.FailClose {
			ctx.Metrics.ErrorsTotal.With(prometheus.Labels{"type": "rate_limited"}).Inc()
			sendServfail(ctx.Request, ctx.Send)
			return ErrRateLimited
		}
		return nil
	}
	if val > int64(h.Rate) {
		slog.Warn("Rate limit exceeded", "client", ctx.ClientIP, "qps", h.Rate)
		ctx.Metrics.ErrorsTotal.With(prometheus.Labels{"type": "rate_limited"}).Inc()
		switch h.Action {
		case "drop":
		default:
			sendServfail(ctx.Request, ctx.Send)
		}
		return ErrRateLimited
	}
	return nil
}

func sendServfail(req *dns.Message, send func([]byte) error) {
	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   req.Header.Flags & ^uint16(0x002F) | 0x8000 | 0x0002,
			QDCount: 1,
		},
		Questions: req.Questions,
	}
	packed := resp.Pack()
	if err := send(packed); err != nil {
		slog.Error("Error writing SERVFAIL", "error", err)
	}
}
