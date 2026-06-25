package hooks

import (
	"strings"
	"sync"

	"github.com/bata94/northstar/dns"
)

type qminimizeState struct {
	mu        sync.Mutex
	originals map[*dns.Message]string
}

type QMinimizerPreHook struct {
	enabled    bool
	priority   int
	keepLabels int
	state      *qminimizeState
}

type QMinimizerPostHook struct {
	enabled  bool
	priority int
	state    *qminimizeState
}

func NewQMinimizerHooks(enabled bool, prePriority, postPriority, keepLabels int) (*QMinimizerPreHook, *QMinimizerPostHook) {
	if keepLabels < 2 {
		keepLabels = 2
	}
	s := &qminimizeState{originals: make(map[*dns.Message]string)}
	return &QMinimizerPreHook{
			enabled:    enabled,
			priority:   prePriority,
			keepLabels: keepLabels,
			state:      s,
		}, &QMinimizerPostHook{
			enabled:  enabled,
			priority: postPriority,
			state:    s,
		}
}

func (h *QMinimizerPreHook) Name() string  { return "qminimizer" }
func (h *QMinimizerPreHook) Priority() int { return h.priority }
func (h *QMinimizerPreHook) Enabled() bool { return h.enabled }

func (h *QMinimizerPreHook) Lifecycle() Lifecycle {
	return PreResolve
}

func (h *QMinimizerPreHook) Handle(ctx *Context) error {
	if len(ctx.Request.Questions) == 0 {
		return nil
	}
	q := &ctx.Request.Questions[0]
	original := q.Name

	labels := strings.Split(strings.TrimSuffix(original, "."), ".")
	if len(labels) <= h.keepLabels {
		return nil
	}

	minimized := strings.Join(labels[len(labels)-h.keepLabels:], ".")

	h.state.mu.Lock()
	h.state.originals[ctx.Request] = original
	h.state.mu.Unlock()

	q.Name = minimized
	return nil
}

func (h *QMinimizerPostHook) Name() string  { return "qminimizer-restore" }
func (h *QMinimizerPostHook) Priority() int { return h.priority }
func (h *QMinimizerPostHook) Enabled() bool { return h.enabled }

func (h *QMinimizerPostHook) Lifecycle() Lifecycle {
	return PostResolve
}

func (h *QMinimizerPostHook) Handle(ctx *Context) error {
	h.state.mu.Lock()
	original, ok := h.state.originals[ctx.Request]
	if !ok {
		h.state.mu.Unlock()
		return nil
	}
	delete(h.state.originals, ctx.Request)
	h.state.mu.Unlock()

	if len(ctx.Request.Questions) > 0 {
		ctx.Request.Questions[0].Name = original
	}

	if ctx.Entry == nil {
		return nil
	}

	minimized := ctx.Request.Questions[0].Name

	for _, rrs := range [][]dns.ResourceRecord{ctx.Entry.Answers, ctx.Entry.Authorities, ctx.Entry.Additionals} {
		for i := range rrs {
			if rrs[i].Name == minimized {
				rrs[i].Name = original
			}
		}
	}
	return nil
}
