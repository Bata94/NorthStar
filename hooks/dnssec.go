// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package hooks

import (
	"log/slog"
	"time"

	"github.com/bata94/northstar/dns"
)

type DnssecHook struct {
	enabled     bool
	priority    int
	validation  string
	trustAnchor string
}

func NewDnssecHook(enabled bool, priority int, validation, trustAnchor string) *DnssecHook {
	return &DnssecHook{
		enabled:     enabled,
		priority:    priority,
		validation:  validation,
		trustAnchor: trustAnchor,
	}
}

func (h *DnssecHook) Name() string {
	return "dnssec"
}

func (h *DnssecHook) Lifecycle() Lifecycle {
	return PostResolve
}

func (h *DnssecHook) Priority() int {
	return h.priority
}

func (h *DnssecHook) Enabled() bool {
	return h.enabled
}

func (h *DnssecHook) Handle(ctx *Context) error {
	if !h.enabled || ctx.Entry == nil {
		return nil
	}

	if ctx.Request.Header.Flags&0x0010 != 0 {
		return nil
	}

	_, do := findOPT(ctx.Request)
	if !do {
		return nil
	}

	if len(ctx.Entry.Answers) == 0 {
		return nil
	}

	rrsigs, rrsets := groupRRSIGs(ctx.Entry.Authorities, ctx.Entry.Answers)
	if len(rrsigs) == 0 {
		return nil
	}

	matched := 0
	for typeCovered, sigs := range rrsigs {
		rrset := rrsets[typeCovered]
		if len(rrset) == 0 {
			continue
		}
		for _, sig := range sigs {
			now := uint32(time.Now().Unix())
			if sig.SigInception > now || sig.SigExpiration < now {
				continue
			}

			dnskey := findDNSKEY(ctx.Entry.Authorities, sig.SignerName, sig.KeyTag)
			if dnskey == nil {
				continue
			}

			pubKey, err := dns.DNSKEYPublicKey(dnskey)
			if err != nil {
				slog.Debug("DNSSEC: failed to extract public key", "signer", sig.SignerName, "error", err)
				continue
			}

			if err := dns.VerifyRRSIG(rrset, sig, pubKey); err != nil {
				slog.Debug("DNSSEC: signature verification failed", "type", typeCovered, "signer", sig.SignerName, "error", err)
				if ctx.Metrics != nil {
					ctx.Metrics.DnssecValidationStatus.WithLabelValues("failure").Inc()
				}
				if h.validation == "required" {
					slog.Warn("DNSSEC: required validation failed, returning SERVFAIL", "domain", ctx.Request.Question())
					return ErrHookStop
				}
				return nil
			}
			matched++
		}
	}

	if matched > 0 {
		ctx.Entry.AuthenticData = true
		slog.Debug("DNSSEC: validation successful", "domain", ctx.Request.Question(), "rrsigs", matched)
		if ctx.Metrics != nil {
			ctx.Metrics.DnssecValidationStatus.WithLabelValues("success").Inc()
		}
	} else if ctx.Metrics != nil {
		ctx.Metrics.DnssecValidationStatus.WithLabelValues("skipped").Inc()
	}

	return nil
}

func findOPT(req *dns.Message) (size uint16, do bool) {
	for _, rr := range req.Additionals {
		if rr.Type == dns.TypeOPT {
			return rr.Class, rr.TTL&0x00008000 != 0
		}
	}
	return 512, false
}

func groupRRSIGs(authorities, answers []dns.ResourceRecord) (map[uint16][]*dns.RRSIG, map[uint16][]dns.ResourceRecord) {
	rrsigs := make(map[uint16][]*dns.RRSIG)
	rrsets := make(map[uint16][]dns.ResourceRecord)

	all := append(append([]dns.ResourceRecord{}, answers...), authorities...)
	for _, rr := range all {
		if rr.Type == dns.TypeRRSIG {
			sig, err := dns.ParseRRSIG(&rr)
			if err != nil {
				continue
			}
			rrsigs[sig.TypeCovered] = append(rrsigs[sig.TypeCovered], sig)
		} else {
			rrsets[rr.Type] = append(rrsets[rr.Type], rr)
		}
	}
	return rrsigs, rrsets
}

func findDNSKEY(rrs []dns.ResourceRecord, signerName string, keyTag uint16) *dns.DNSKEY {
	for _, rr := range rrs {
		if rr.Type == dns.TypeDNSKEY {
			dnskey, err := dns.ParseDNSKEY(&rr)
			if err != nil {
				continue
			}
			if dns.DNSKEYKeyTag(signerName, dnskey.PublicKey, dnskey.Algorithm) == keyTag {
				return dnskey
			}
		}
	}
	return nil
}
