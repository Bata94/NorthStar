package hooks

import (
	"github.com/bata94/northstar/filter"
)

type ClientStatsHook struct {
	enabled   bool
	priority  int
	collector *filter.ClientStatsCollector
}

func NewClientStatsHook(enabled bool, priority int, collector *filter.ClientStatsCollector) *ClientStatsHook {
	return &ClientStatsHook{
		enabled:   enabled && collector != nil,
		priority:  priority,
		collector: collector,
	}
}

func (h *ClientStatsHook) Name() string         { return "client_stats" }
func (h *ClientStatsHook) Lifecycle() Lifecycle { return PostResponse }
func (h *ClientStatsHook) Priority() int        { return h.priority }
func (h *ClientStatsHook) Enabled() bool {
	return h.enabled && h.collector != nil && h.collector.Enabled()
}

func (h *ClientStatsHook) Handle(ctx *Context) error {
	if !h.Enabled() || ctx.Request == nil || len(ctx.Request.Questions) == 0 {
		return nil
	}

	domain := ctx.Request.Questions[0].Name
	qtype := ctx.Request.Questions[0].Type
	blocked := ctx.Response != nil && ctx.Response.Header.Flags&0x000F == 3

	h.collector.RecordQuery(ctx.ClientIP, domain, qtype, blocked)
	return nil
}
