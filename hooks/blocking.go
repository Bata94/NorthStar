package hooks

import (
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/filter"
	"github.com/bata94/northstar/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type BlockingHook struct {
	priority   int
	enabled    bool
	filter     *filter.Filter
	rpz        *filter.RPZSet
	action     string
	sinkholeIP net.IP
	domainRPS  int
	metrics    *metrics.Metrics
}

func NewBlockingHook(cfg struct {
	Enabled      bool
	Priority     int
	BlockAction  string
	SinkholeAddr string
	Blocklists   []string
	Allowlists   []string
	DomainRPS    int
	RPZ          []struct{ Path, Action string }
}, m *metrics.Metrics) (*BlockingHook, error) {
	f, err := filter.NewFilter(cfg.Blocklists, cfg.Allowlists)
	if err != nil {
		return nil, err
	}

	action := cfg.BlockAction
	if action == "" {
		action = "nxdomain"
	}

	sinkIP := net.ParseIP(cfg.SinkholeAddr)
	if sinkIP == nil {
		sinkIP = net.ParseIP("127.0.0.1")
	}

	var rpzSet *filter.RPZSet
	if len(cfg.RPZ) > 0 {
		rpzSet, err = filter.NewRPZSet(cfg.RPZ)
		if err != nil {
			return nil, err
		}
	}

	return &BlockingHook{
		priority:   cfg.Priority,
		enabled:    cfg.Enabled,
		filter:     f,
		rpz:        rpzSet,
		action:     action,
		sinkholeIP: sinkIP,
		domainRPS:  cfg.DomainRPS,
		metrics:    m,
	}, nil
}

func (h *BlockingHook) Name() string         { return "blocking" }
func (h *BlockingHook) Lifecycle() Lifecycle { return PreResolve }
func (h *BlockingHook) Priority() int        { return h.priority }
func (h *BlockingHook) Enabled() bool        { return h.enabled }

func (h *BlockingHook) Handle(ctx *Context) error {
	if len(ctx.Request.Questions) == 0 {
		return nil
	}

	q := ctx.Request.Questions[0]
	domain := q.Name
	domain = trimTrailingDot(domain)

	action := h.checkBlocked(domain, ctx)
	if action == "" {
		return nil
	}

	slog.Warn("Query blocked", "domain", domain, "action", action, "client", ctx.ClientIP)

	maxPayload := extractMaxPayload(ctx.Request)

	sendBlockedResponse(ctx.Request, action, h.sinkholeIP, q, maxPayload, ctx.Send)

	h.metrics.BlockedTotal.With(prometheus.Labels{
		"action": action,
		"qtype":  strconv.Itoa(int(q.Type)),
	}).Inc()

	return ErrBlocked
}

func (h *BlockingHook) checkBlocked(domain string, ctx *Context) string {
	if h.filter != nil && h.filter.IsBlocked(domain) {
		return h.action
	}

	if h.rpz != nil {
		if rpzAction, ok := h.rpz.Match(domain); ok {
			return rpzAction
		}
	}

	if h.domainRPS > 0 {
		key := "northstar:domainrate:" + domain + ":" + strconv.FormatInt(time.Now().Unix(), 10)
		val, err := ctx.Cache.Incr(ctx.Ctx, key, time.Second)
		if err == nil && val > int64(h.domainRPS) {
			return h.action
		}
	}

	return ""
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func extractMaxPayload(req *dns.Message) uint16 {
	for _, rr := range req.Additionals {
		if rr.Type == 41 {
			return rr.Class
		}
	}
	return 512
}

func sendBlockedResponse(req *dns.Message, action string, sinkholeIP net.IP, q dns.Question, maxPayload uint16, send func([]byte) error) {
	var (
		answers     []dns.ResourceRecord
		authorities []dns.ResourceRecord
		flags       uint16
		rcode       uint16
	)

	switch action {
	case "sinkhole":
		rcode = 0
		flags = 0x8000 | 0x0080
		var rdata []byte
		var rrType uint16
		if sinkholeIP.To4() != nil && q.Type == 1 {
			rdata = []byte(sinkholeIP.To4())
			rrType = 1
		} else if sinkholeIP.To16() != nil && sinkholeIP.To4() == nil && q.Type == 28 {
			rdata = []byte(sinkholeIP.To16())
			rrType = 28
		} else if q.Type == 28 {
			ipv6 := net.ParseIP("::1")
			rdata = []byte(ipv6.To16())
			rrType = 28
		} else {
			rdata = []byte(sinkholeIP.To4())
			rrType = 1
		}
		answers = append(answers, dns.ResourceRecord{
			Name:     q.Name,
			Type:     rrType,
			Class:    1,
			TTL:      60,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		})
	case "refused":
		rcode = 5
	case "nxdomain":
		rcode = 3
	case "drop":
		return
	default:
		rcode = 3
	}

	flags |= rcode

	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: uint16(len(answers)),
			NSCount: uint16(len(authorities)),
			ARCount: 1,
		},
		Questions:   req.Questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: []dns.ResourceRecord{{
			Name:  "",
			Type:  41,
			Class: maxPayload,
		}},
	}
	packed := resp.Pack()
	if err := send(packed); err != nil {
		slog.Error("Error writing blocked response", "error", err)
	}
}
