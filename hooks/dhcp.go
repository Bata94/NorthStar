package hooks

import (
	"log/slog"
	"net"
	"strings"

	"github.com/bata94/northstar/dhcp"
	"github.com/bata94/northstar/dns"
)

type DHCPHook struct {
	enabled bool
	domain  string
	ttl     uint32
	watcher *dhcp.Watcher
}

func NewDHCPHook(watcher *dhcp.Watcher, domain string, ttl uint32) *DHCPHook {
	return &DHCPHook{
		enabled: watcher != nil,
		domain:  strings.TrimSuffix(strings.TrimSuffix(domain, "."), "."),
		ttl:     ttl,
		watcher: watcher,
	}
}

func (h *DHCPHook) Name() string         { return "dhcp" }
func (h *DHCPHook) Lifecycle() Lifecycle { return PreResolve }
func (h *DHCPHook) Priority() int        { return 45 }
func (h *DHCPHook) Enabled() bool        { return h.enabled }

func (h *DHCPHook) Handle(ctx *Context) error {
	if !h.enabled || h.watcher == nil || len(ctx.Request.Questions) == 0 {
		return nil
	}

	q := ctx.Request.Questions[0]
	qname := strings.TrimSuffix(q.Name, ".")

	if q.Type == dns.TypeAXFR || q.Type == dns.TypeIXFR {
		return nil
	}

	leases := h.watcher.ActiveLeases()
	if len(leases) == 0 {
		return nil
	}

	answers := resolveDHCPQuery(qname, q.Type, leases, h.domain, h.ttl)
	if len(answers) == 0 {
		return nil
	}

	resp := &dns.Message{
		Header: dns.Header{
			ID:      ctx.Request.Header.ID,
			Flags:   0x8580,
			QDCount: 1,
			ANCount: uint16(len(answers)),
		},
		Questions: ctx.Request.Questions,
		Answers:   answers,
		Additionals: []dns.ResourceRecord{{
			Name:  "",
			Type:  dns.TypeOPT,
			Class: 1232,
		}},
	}
	resp.Header.ARCount = 1

	packed := resp.Pack()
	slog.Debug("DHCP hook response", "domain", q.Name, "type", q.Type, "answers", len(answers))
	if err := ctx.Send(packed); err != nil {
		slog.Error("Error writing DHCP response", "error", err)
		return err
	}
	return ErrHookStop
}

func resolveDHCPQuery(qname string, qtype uint16, leases []dhcp.Lease, domain string, ttl uint32) []dns.ResourceRecord {
	qname = strings.TrimSuffix(qname, ".")

	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		return resolveHostname(qname, qtype, leases, domain, ttl)
	case dns.TypePTR:
		return resolvePTR(qname, leases, domain, ttl)
	}

	return nil
}

func resolveHostname(qname string, qtype uint16, leases []dhcp.Lease, domain string, ttl uint32) []dns.ResourceRecord {
	suffix := "." + domain
	if !strings.HasSuffix(qname, suffix) && qname != domain {
		return nil
	}

	hostname := qname
	if strings.HasSuffix(qname, suffix) {
		hostname = qname[:len(qname)-len(suffix)]
	}

	if hostname == "" {
		return nil
	}

	for _, lease := range leases {
		if lease.Hostname == hostname {
			if qtype == dns.TypeA {
				if ip4 := lease.IP.To4(); ip4 != nil {
					return []dns.ResourceRecord{{
						Name:     qname + ".",
						Type:     dns.TypeA,
						Class:    1,
						TTL:      ttl,
						RDLength: uint16(len(ip4)),
						RData:    ip4,
					}}
				}
			}
			if qtype == dns.TypeAAAA {
				if ip16 := lease.IP.To16(); ip16 != nil && lease.IP.To4() == nil {
					return []dns.ResourceRecord{{
						Name:     qname + ".",
						Type:     dns.TypeAAAA,
						Class:    1,
						TTL:      ttl,
						RDLength: uint16(len(ip16)),
						RData:    ip16,
					}}
				}
			}
		}
	}

	return nil
}

func resolvePTR(qname string, leases []dhcp.Lease, domain string, ttl uint32) []dns.ResourceRecord {
	if !strings.HasSuffix(qname, ".in-addr.arpa") {
		return nil
	}

	ipStr := strings.TrimSuffix(qname, ".in-addr.arpa")
	parts := strings.Split(ipStr, ".")
	if len(parts) != 4 {
		return nil
	}

	reversed := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
	targetIP := dhcpParseIP(reversed)
	if targetIP == nil {
		return nil
	}

	for _, lease := range leases {
		if lease.IP.Equal(targetIP) {
			fqdn := lease.Hostname + "." + domain + "."
			ptrData := encodeDNSNameForPTR(fqdn)
			return []dns.ResourceRecord{{
				Name:     qname + ".",
				Type:     dns.TypePTR,
				Class:    1,
				TTL:      ttl,
				RDLength: uint16(len(ptrData)),
				RData:    ptrData,
			}}
		}
	}

	return nil
}

func dhcpParseIP(s string) net.IP {
	return net.ParseIP(s)
}

func encodeDNSNameForPTR(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}
