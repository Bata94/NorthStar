package hooks

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type ResponseRateLimitHook struct {
	enabled  bool
	priority int
	rate     int
	slip     int
	action   string
}

func NewResponseRateLimitHook(rate, slip int, action string, priority int, enabled bool) *ResponseRateLimitHook {
	return &ResponseRateLimitHook{
		enabled:  enabled,
		priority: priority,
		rate:     rate,
		slip:     slip,
		action:   action,
	}
}

func (h *ResponseRateLimitHook) Name() string         { return "response_rate_limiting" }
func (h *ResponseRateLimitHook) Lifecycle() Lifecycle { return PreResponse }
func (h *ResponseRateLimitHook) Priority() int        { return h.priority }
func (h *ResponseRateLimitHook) Enabled() bool        { return h.enabled && h.rate > 0 }

func (h *ResponseRateLimitHook) Handle(ctx *Context) error {
	if ctx.Response == nil || len(ctx.Request.Questions) == 0 {
		return nil
	}

	rcode := ctx.Response.Header.Flags & 0x000F
	qname := ctx.Request.Questions[0].Name
	key := fmt.Sprintf("northstar:rrl:%s:%d", ctx.ClientIP, rcode)

	val, err := ctx.Cache.Incr(ctx.Ctx, key, time.Second)
	if err != nil {
		slog.Error("RRL cache error", "error", err)
		return nil
	}

	if val <= int64(h.rate) {
		return nil
	}

	slog.Warn("RRL exceeded", "client", ctx.ClientIP, "rcode", rcode, "qname", qname, "count", val, "rate", h.rate)

	switch h.action {
	case "truncate":
		ctx.Response.Header.Flags |= 0x0200
		ctx.Response.Header.ANCount = 0
		ctx.Response.Header.NSCount = 0
		ctx.Response.Header.ARCount = 0
		ctx.Response.Answers = nil
		ctx.Response.Authorities = nil
		ctx.Response.Additionals = nil
		return nil
	default:
		if h.slip > 0 && val%int64(h.slip) == 1 {
			return nil
		}
		ctx.Metrics.RRLDroppedTotal.With(prometheus.Labels{
			"action": "drop",
			"rcode":  fmt.Sprintf("%d", rcode),
		}).Inc()
		return ErrHookStop
	}
}
