package hooks

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
	"github.com/prometheus/client_golang/prometheus"
)

type RateLimitHook struct {
	Rate        int
	Action      string
	FailClose   bool
	priority    int
	enabled     bool
	tokenBucket cache.TokenBucket
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

func NewTokenBucketRateLimitHook(rate int, burst int, action string, priority int, enabled bool, _ string) *RateLimitHook {
	var tb cache.TokenBucket
	if rate > 0 && enabled {
		tb = cache.NewMemoryTokenBucket(rate, burst)
	}
	return &RateLimitHook{
		Rate:        rate,
		Action:      action,
		priority:    priority,
		enabled:     enabled,
		tokenBucket: tb,
	}
}

func (h *RateLimitHook) Name() string         { return "rate_limiting" }
func (h *RateLimitHook) Lifecycle() Lifecycle { return PreResolve }
func (h *RateLimitHook) Priority() int        { return h.priority }
func (h *RateLimitHook) Enabled() bool        { return h.enabled && (h.Rate > 0 || h.tokenBucket != nil) }

func (h *RateLimitHook) Close() {
	if h.tokenBucket != nil {
		if err := h.tokenBucket.Close(); err != nil {
			slog.Error("Failed to close token bucket", "error", err)
		}
	}
}

func (h *RateLimitHook) Handle(ctx *Context) error {
	if h.tokenBucket != nil {
		return h.handleTokenBucket(ctx)
	}
	return h.handleFixedWindow(ctx)
}

func (h *RateLimitHook) handleTokenBucket(ctx *Context) error {
	allowed, err := h.tokenBucket.TryConsume(ctx.Ctx, ctx.ClientIP)
	if err != nil {
		slog.Error("Token bucket error", "error", err)
		// On error, allow the query through (fail-open)
		return nil
	}
	if !allowed {
		slog.Warn("Rate limit exceeded (token bucket)", "client", ctx.ClientIP, "rate", h.Rate)
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

func (h *RateLimitHook) handleFixedWindow(ctx *Context) error {
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
