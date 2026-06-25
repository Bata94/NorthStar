package hooks

import (
	"log/slog"
	"net"
	"strings"

	"github.com/bata94/northstar/dns"
)

type SpecialDomainHook struct {
	enabled  bool
	priority int
}

func NewSpecialDomainHook(enabled bool, priority int) *SpecialDomainHook {
	return &SpecialDomainHook{
		enabled:  enabled,
		priority: priority,
	}
}

func (h *SpecialDomainHook) Name() string {
	return "special_domain"
}

func (h *SpecialDomainHook) Lifecycle() Lifecycle {
	return PreResolve
}

func (h *SpecialDomainHook) Priority() int {
	return h.priority
}

func (h *SpecialDomainHook) Enabled() bool {
	return h.enabled
}

func (h *SpecialDomainHook) Handle(ctx *Context) error {
	if !h.enabled {
		return nil
	}

	q := ctx.Request.Questions[0]
	name := strings.TrimSuffix(q.Name, ".")
	labels := strings.Split(strings.ToLower(name), ".")
	if len(labels) == 0 {
		return nil
	}
	tld := labels[len(labels)-1]

	maxPayload := uint16(512)
	for _, rr := range ctx.Request.Additionals {
		if rr.Type == dns.TypeOPT {
			maxPayload = rr.Class
			break
		}
	}

	switch tld {
	case "localhost":
		return h.respondLocalhost(ctx, q, maxPayload)
	case "invalid", "test":
		return h.respondNXDOMAIN(ctx, q, maxPayload)
	case "local":
		return h.respondRefused(ctx, q, maxPayload)
	}

	if len(labels) >= 2 {
		sld := labels[len(labels)-2]
		if sld == "example" && (tld == "com" || tld == "net" || tld == "org") {
			return h.respondNXDOMAIN(ctx, q, maxPayload)
		}
	}

	return nil
}

func (h *SpecialDomainHook) respondLocalhost(ctx *Context, q dns.Question, maxPayload uint16) error {
	slog.Debug("Special domain localhost", "domain", q.Name)

	var answers []dns.ResourceRecord
	authRRs := soaRecords("@", 86400)

	switch q.Type {
	case dns.TypeA, dns.TypeANY:
		answers = append(answers, dns.ResourceRecord{
			Name:     q.Name,
			Type:     dns.TypeA,
			Class:    1,
			TTL:      86400,
			RDLength: 4,
			RData:    net.IPv4(127, 0, 0, 1).To4(),
		})
	case dns.TypeAAAA:
		answers = append(answers, dns.ResourceRecord{
			Name:     q.Name,
			Type:     dns.TypeAAAA,
			Class:    1,
			TTL:      86400,
			RDLength: 16,
			RData:    net.IPv6loopback,
		})
	}

	if q.Type == dns.TypeANY {
		answers = append(answers, dns.ResourceRecord{
			Name:     q.Name,
			Type:     dns.TypeAAAA,
			Class:    1,
			TTL:      86400,
			RDLength: 16,
			RData:    net.IPv6loopback,
		})
	}

	resp := dns.Message{
		Header: dns.Header{
			ID:      ctx.Request.Header.ID,
			Flags:   0x8000 | 0x0080,
			QDCount: 1,
			ANCount: uint16(len(answers)),
			NSCount: uint16(len(authRRs)),
			ARCount: 1,
		},
		Questions:   ctx.Request.Questions,
		Answers:     answers,
		Authorities: authRRs,
		Additionals: []dns.ResourceRecord{{
			Name: "", Type: dns.TypeOPT, Class: maxPayload,
		}},
	}
	packed := resp.Pack()
	if err := ctx.Send(packed); err != nil {
		slog.Error("Error sending localhost response", "error", err)
	}
	return ErrHookStop
}

func (h *SpecialDomainHook) respondNXDOMAIN(ctx *Context, q dns.Question, maxPayload uint16) error {
	slog.Debug("Special domain NXDOMAIN", "domain", q.Name)

	authRRs := soaRecords("@", 86400)
	resp := dns.Message{
		Header: dns.Header{
			ID:      ctx.Request.Header.ID,
			Flags:   0x8000 | 0x0080 | 0x0003,
			QDCount: 1,
			NSCount: uint16(len(authRRs)),
			ARCount: 1,
		},
		Questions:   ctx.Request.Questions,
		Authorities: authRRs,
		Additionals: []dns.ResourceRecord{{
			Name: "", Type: dns.TypeOPT, Class: maxPayload,
		}},
	}
	packed := resp.Pack()
	if err := ctx.Send(packed); err != nil {
		slog.Error("Error sending NXDOMAIN", "error", err)
	}
	return ErrHookStop
}

func (h *SpecialDomainHook) respondRefused(ctx *Context, q dns.Question, maxPayload uint16) error {
	slog.Debug("Special domain REFUSED", "domain", q.Name)

	resp := dns.Message{
		Header: dns.Header{
			ID:      ctx.Request.Header.ID,
			Flags:   0x8000 | 0x0005,
			QDCount: 1,
			ARCount: 1,
		},
		Questions: ctx.Request.Questions,
		Additionals: []dns.ResourceRecord{{
			Name: "", Type: dns.TypeOPT, Class: maxPayload,
		}},
	}
	packed := resp.Pack()
	if err := ctx.Send(packed); err != nil {
		slog.Error("Error sending REFUSED", "error", err)
	}
	return ErrHookStop
}

func soaRecords(origin string, ttl uint32) []dns.ResourceRecord {
	mname := origin
	rname := "hostmaster." + origin
	if origin == "@" {
		mname = "localhost."
		rname = "hostmaster.localhost."
	}
	rdata := make([]byte, 0, 22)
	for _, s := range []string{mname, rname} {
		labels := strings.Split(strings.TrimSuffix(s, "."), ".")
		for _, l := range labels {
			rdata = append(rdata, byte(len(l)))
			rdata = append(rdata, l...)
		}
		rdata = append(rdata, 0)
	}
	serial := uint32(2026000001)
	refresh := uint32(3600)
	retry := uint32(900)
	expire := uint32(86400)
	minimum := uint32(86400)
	for _, v := range []uint32{serial, refresh, retry, expire, minimum} {
		rdata = append(rdata, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return []dns.ResourceRecord{{
		Name:     origin,
		Type:     dns.TypeSOA,
		Class:    1,
		TTL:      ttl,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}}
}
