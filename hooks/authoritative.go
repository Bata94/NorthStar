package hooks

import (
	"log/slog"
	"strconv"

	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/zone"
)

type AuthoritativeHook struct {
	zoneSet *zone.Set
	enabled bool
}

func NewAuthoritativeHook(zones []*zone.Zone) *AuthoritativeHook {
	return &AuthoritativeHook{
		zoneSet: zone.NewSet(zones),
		enabled: len(zones) > 0,
	}
}

func (h *AuthoritativeHook) ZoneSet() *zone.Set { return h.zoneSet }
func (h *AuthoritativeHook) ReplaceZones(zones []*zone.Zone) {
	h.zoneSet.Replace(zones)
	h.enabled = len(zones) > 0
}

func (h *AuthoritativeHook) Name() string         { return "authoritative" }
func (h *AuthoritativeHook) Lifecycle() Lifecycle { return PreResolve }
func (h *AuthoritativeHook) Priority() int        { return 50 }
func (h *AuthoritativeHook) Enabled() bool        { return h.enabled }

func (h *AuthoritativeHook) Handle(ctx *Context) error {
	if !h.enabled || len(ctx.Request.Questions) == 0 {
		return nil
	}

	q := ctx.Request.Questions[0]
	domain := q.Name

	z := h.zoneSet.Lookup(domain)
	if z == nil {
		return nil
	}

	if ctx.Metrics != nil {
		ctx.Metrics.ZoneQueriesTotal.WithLabelValues(z.Name, strconv.Itoa(int(q.Type))).Inc()
	}

	slog.Debug("Serving from authoritative zone", "domain", domain, "type", q.Type, "zone", z.Name)

	var resp *dns.Message
	if q.Type == dns.TypeAXFR || q.Type == dns.TypeIXFR {
		resp = zone.BuildRefusedResponse(ctx.Request)
	} else {
		resp = zone.BuildResponse(ctx.Request, z, domain, q.Type)
		resp = zone.AttachDNSSEC(z, resp, ctx.Request, z.SigningKey)
	}

	packed := resp.Pack()
	if err := ctx.Send(packed); err != nil {
		slog.Error("Error writing authoritative response", "error", err)
	}

	return ErrHookStop
}
