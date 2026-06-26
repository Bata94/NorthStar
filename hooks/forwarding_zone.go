package hooks

import (
	"log/slog"
	"strings"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
)

type ForwardingZoneHook struct {
	enabled bool
	zones   []config.ForwardingZoneConfig
}

func NewForwardingZoneHook(zones []config.ForwardingZoneConfig) *ForwardingZoneHook {
	return &ForwardingZoneHook{
		enabled: len(zones) > 0,
		zones:   zones,
	}
}

func (h *ForwardingZoneHook) ReplaceZones(zones []config.ForwardingZoneConfig) {
	h.zones = zones
	h.enabled = len(zones) > 0
}

func (h *ForwardingZoneHook) Name() string         { return "forwarding_zone" }
func (h *ForwardingZoneHook) Lifecycle() Lifecycle { return PreResolve }
func (h *ForwardingZoneHook) Priority() int        { return 55 }
func (h *ForwardingZoneHook) Enabled() bool        { return h.enabled }

func (h *ForwardingZoneHook) Handle(ctx *Context) error {
	if !h.enabled || len(ctx.Request.Questions) == 0 {
		return nil
	}

	q := ctx.Request.Questions[0]
	domain := strings.TrimSuffix(q.Name, ".")

	if q.Type == dns.TypeAXFR || q.Type == dns.TypeIXFR {
		return nil
	}

	for _, z := range h.zones {
		if !matchForwardingZone(domain, z.Domain) {
			continue
		}
		if len(z.Upstreams) == 0 {
			continue
		}

		slog.Debug("Forwarding zone match",
			"domain", q.Name,
			"zone", z.Domain,
			"upstreams", z.Upstreams,
			"mode", z.Mode,
		)

		ctx.PreferredUpstream = z.Upstreams[0]

		if z.Mode == "forward-only" {
			ctx.ForwardOnly = true
		}

		return nil
	}

	return nil
}

func matchForwardingZone(domain, zoneDomain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	zoneDomain = strings.TrimSuffix(zoneDomain, ".")
	if domain == zoneDomain {
		return true
	}
	if strings.HasSuffix(domain, "."+zoneDomain) {
		return true
	}
	return false
}
