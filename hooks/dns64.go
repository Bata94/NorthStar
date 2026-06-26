// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package hooks

import (
	"log/slog"
	"net/netip"

	"github.com/bata94/northstar/dns"
)

type Dns64Hook struct {
	enabled  bool
	priority int
	prefix   string
}

func NewDns64Hook(enabled bool, priority int, prefix string) *Dns64Hook {
	return &Dns64Hook{
		enabled:  enabled,
		priority: priority,
		prefix:   prefix,
	}
}

func (h *Dns64Hook) Name() string {
	return "dns64"
}

func (h *Dns64Hook) Lifecycle() Lifecycle {
	return PostResolve
}

func (h *Dns64Hook) Priority() int {
	return h.priority
}

func (h *Dns64Hook) Enabled() bool {
	return h.enabled
}

func (h *Dns64Hook) Handle(ctx *Context) error {
	if !h.enabled {
		return nil
	}

	q := ctx.Request.Questions[0]
	if q.Type != dns.TypeAAAA {
		return nil
	}

	if ctx.Entry == nil {
		return nil
	}

	hasAAAA := false
	for _, rr := range ctx.Entry.Answers {
		if rr.Type == dns.TypeAAAA && len(rr.RData) == 16 {
			hasAAAA = true
			break
		}
	}

	if hasAAAA {
		return nil
	}

	prefix, err := netip.ParsePrefix(h.prefix)
	if err != nil {
		slog.Error("DNS64: invalid NAT64 prefix", "prefix", h.prefix, "error", err)
		return nil
	}

	prefixBytes := prefix.Addr().AsSlice()
	prefixBits := prefix.Bits()

	aRecords := h.lookupARecords(ctx, q.Name)
	if len(aRecords) == 0 && ctx.ResolveFunc != nil {
		resolved, err := ctx.ResolveFunc(ctx.Ctx, q.Name, dns.TypeA)
		if err == nil && resolved != nil {
			aRecords = h.filterARecords(resolved.Answers)
			if len(aRecords) > 0 {
				slog.Debug("DNS64: triggered A record lookup for synthesis",
					"domain", q.Name, "count", len(aRecords))
			}
		}
	}
	if len(aRecords) == 0 {
		return nil
	}

	slog.Info("DNS64: synthesizing AAAA records", "domain", q.Name, "count", len(aRecords))

	var synthetic []dns.ResourceRecord
	for _, a := range aRecords {
		if a.Type != dns.TypeA || len(a.RData) != 4 {
			continue
		}
		ipv6 := make([]byte, 16)
		switch prefixBits {
		case 96:
			copy(ipv6, prefixBytes[:12])
			copy(ipv6[12:], a.RData)
		case 64:
			copy(ipv6, prefixBytes[:8])
			ipv6[8] = 0
			ipv6[9] = 0
			ipv6[10] = 0
			ipv6[11] = 0
			copy(ipv6[12:], a.RData)
		case 32:
			copy(ipv6, prefixBytes[:4])
			ipv6[4] = 0
			ipv6[5] = 0
			ipv6[6] = 0
			ipv6[7] = 0
			copy(ipv6[8:12], a.RData)
			copy(ipv6[12:], a.RData)
		default:
			slog.Warn("DNS64: unsupported prefix length, must be 32, 64, or 96", "prefix_bits", prefixBits)
			continue
		}
		synthetic = append(synthetic, dns.ResourceRecord{
			Name:     q.Name,
			Type:     dns.TypeAAAA,
			Class:    a.Class,
			TTL:      a.TTL,
			RDLength: 16,
			RData:    ipv6,
		})
	}

	if len(synthetic) > 0 {
		ctx.Entry.Answers = append(ctx.Entry.Answers, synthetic...)
		if ctx.Response != nil {
			ctx.Response.Answers = append(ctx.Response.Answers, synthetic...)
			ctx.Response.Header.ANCount = uint16(len(ctx.Response.Answers))
		}
		if ctx.Metrics != nil {
			ctx.Metrics.Dns64SynthesesTotal.Add(float64(len(synthetic)))
		}
	}

	return nil
}

func (h *Dns64Hook) lookupARecords(ctx *Context, domain string) []dns.ResourceRecord {
	if ctx.Cache == nil {
		return nil
	}

	entry, found := ctx.Cache.Peek(ctx.Ctx, domain, dns.TypeA)
	if !found || entry.Expired() {
		return nil
	}

	return h.filterARecords(entry.Answers)
}

func (h *Dns64Hook) filterARecords(answers []dns.ResourceRecord) []dns.ResourceRecord {
	var aRecords []dns.ResourceRecord
	for _, rr := range answers {
		if rr.Type == dns.TypeA && len(rr.RData) == 4 {
			aRecords = append(aRecords, rr)
		}
	}
	return aRecords
}
