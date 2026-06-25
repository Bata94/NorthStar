package hooks

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/bata94/northstar/log"
)

type QueryLogHook struct {
	enabled       bool
	priority      int
	dir           string
	prefix        string
	retentionDays int
	mu            sync.Mutex
	w             *log.RotateWriter
}

func NewQueryLogHook(enabled bool, priority int, file string, retentionDays int) *QueryLogHook {
	dir, prefix := filepath.Split(file)
	if dir == "" {
		dir = "."
	}
	dir = filepath.Clean(dir)
	if prefix == "" {
		prefix = "query"
	}
	return &QueryLogHook{
		enabled:       enabled,
		priority:      priority,
		dir:           dir,
		prefix:        prefix,
		retentionDays: retentionDays,
	}
}

func (h *QueryLogHook) Name() string         { return "query_log" }
func (h *QueryLogHook) Lifecycle() Lifecycle { return PostResponse }
func (h *QueryLogHook) Priority() int        { return h.priority }
func (h *QueryLogHook) Enabled() bool        { return h.enabled }

func (h *QueryLogHook) Handle(ctx *Context) error {
	if !h.enabled {
		return nil
	}

	var cacheDecision string
	switch {
	case ctx.Entry == nil:
		cacheDecision = "miss"
	case ctx.Entry.Expired():
		cacheDecision = "stale"
	default:
		cacheDecision = "hit"
	}

	latencyMs := time.Since(ctx.StartTime).Milliseconds()

	rcode := uint8(0)
	if ctx.Response != nil {
		rcode = uint8(ctx.Response.Header.Flags & 0x000F)
	}

	qname := ""
	qtype := ""
	if ctx.Request != nil && len(ctx.Request.Questions) > 0 {
		q := ctx.Request.Questions[0]
		qname = q.Name
		qtype = fmt.Sprintf("%d", q.Type)
	}

	record := fmt.Sprintf("%s,%s,%s,%s,%d,%d,%s,%s\n",
		ctx.StartTime.Format(time.RFC3339),
		ctx.ClientIP,
		qname,
		qtype,
		rcode,
		latencyMs,
		cacheDecision,
		ctx.Upstream,
	)

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.w == nil {
		h.w = log.NewFileRotateWriter(h.dir, h.prefix, h.retentionDays)
	}

	if _, err := h.w.Write([]byte(record)); err != nil {
		slog.Error("Query log: write error", "error", err)
	}

	return nil
}

var _ Hook = (*QueryLogHook)(nil)
