package hooks

import (
	"log/slog"
	"time"

	"github.com/bata94/northstar/acl"
	"github.com/bata94/northstar/dns"
)

type AclHook struct {
	aclSet  *acl.RuleSet
	enabled bool
}

func NewAclHook(rs *acl.RuleSet) *AclHook {
	return &AclHook{
		aclSet:  rs,
		enabled: len(rs.Rules()) > 0,
	}
}

func (h *AclHook) ACLSet() *acl.RuleSet { return h.aclSet }
func (h *AclHook) ReplaceRules(rs *acl.RuleSet) {
	h.aclSet = rs
	h.enabled = len(rs.Rules()) > 0
}

func (h *AclHook) Name() string         { return "acl" }
func (h *AclHook) Lifecycle() Lifecycle { return PreResolve }
func (h *AclHook) Priority() int        { return 150 }
func (h *AclHook) Enabled() bool        { return h.enabled }

func (h *AclHook) Handle(ctx *Context) error {
	if !h.enabled || len(ctx.Request.Questions) == 0 {
		return nil
	}

	q := ctx.Request.Questions[0]
	domain := q.Name

	rule := h.aclSet.Match(ctx.ClientIP, domain, ctx.Network)
	if rule == nil {
		return nil
	}

	switch rule.Action {
	case "allow":
		return nil

	case "refuse":
		slog.Warn("ACL refused query", "client", ctx.ClientIP, "domain", domain, "rule", rule.Name)
		sendRefused(ctx.Request, extractMaxPayload(ctx.Request), ctx.Send)
		return ErrHookStop

	case "drop":
		slog.Warn("ACL dropped query", "client", ctx.ClientIP, "domain", domain, "rule", rule.Name)
		time.Sleep(100 * time.Millisecond)
		return ErrHookStop

	case "route":
		if rule.Upstream != "" {
			ctx.PreferredUpstream = rule.Upstream
			slog.Debug("ACL routed query", "client", ctx.ClientIP, "domain", domain, "upstream", rule.Upstream, "rule", rule.Name)
		}
		return nil

	default:
		return nil
	}
}

func sendRefused(req *dns.Message, maxPayload uint16, send func([]byte) error) {
	flags := uint16(0x8005) // QR=1, RA=0, RCODE=5 (REFUSED)
	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: 0,
			NSCount: 0,
			ARCount: 1,
		},
		Questions: req.Questions,
		Additionals: []dns.ResourceRecord{{
			Name:  "",
			Type:  dns.TypeOPT,
			Class: maxPayload,
		}},
	}
	packed := resp.Pack()
	if err := send(packed); err != nil {
		slog.Error("Error writing refused response", "error", err)
	}
}
