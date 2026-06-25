// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package hooks

import (
	"github.com/bata94/northstar/dns"
)

type EcsHook struct {
	enabled  bool
	priority int
	prefixV4 int
	prefixV6 int
}

func NewEcsHook(enabled bool, priority int, prefixV4, prefixV6 int) *EcsHook {
	return &EcsHook{
		enabled:  enabled,
		priority: priority,
		prefixV4: prefixV4,
		prefixV6: prefixV6,
	}
}

func (h *EcsHook) Name() string {
	return "ecs"
}

func (h *EcsHook) Lifecycle() Lifecycle {
	return PreResolve
}

func (h *EcsHook) Priority() int {
	return h.priority
}

func (h *EcsHook) Enabled() bool {
	return h.enabled
}

func (h *EcsHook) Handle(ctx *Context) error {
	if !h.enabled {
		return nil
	}

	q := ctx.Request.Questions[0]

	prefixLen := h.prefixV4
	if q.Type == dns.TypeAAAA {
		prefixLen = h.prefixV6
	}

	ecsData := dns.BuildECSOption(ctx.ClientIP, prefixLen)
	if ecsData == nil {
		return nil
	}

	ctx.ECSData = ecsData

	if ctx.Metrics != nil {
		family := "v4"
		if q.Type == dns.TypeAAAA {
			family = "v6"
		}
		ctx.Metrics.EcsQueriesTotal.WithLabelValues(family).Inc()
	}

	return nil
}
