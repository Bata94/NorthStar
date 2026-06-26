package hooks

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/filter"
	"github.com/bata94/northstar/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type blockSource string

const (
	sourceBlocklist  blockSource = "blocklist"
	sourceRPZ        blockSource = "rpz"
	sourceDomainRate blockSource = "domain_rate"
)

type BlockingHook struct {
	priority      int
	enabled       bool
	filter        *filter.Filter
	rpz           *filter.RPZSet
	action        string
	sinkholeIP    net.IP
	domainRPS     int
	metrics       *metrics.Metrics
	blocklists    []string
	allowlists    []string
	rpzConfigs    []struct{ Path, Action string }
	urlSources    []*filter.URLSource
	blocklistURLs []config.BlocklistURLConfig
	stats         *filter.BlockingStats
	statsEnabled  bool
}

func NewBlockingHook(cfg struct {
	Enabled         bool
	Priority        int
	BlockAction     string
	SinkholeAddr    string
	Blocklists      []string
	Allowlists      []string
	BlocklistURLs   []config.BlocklistURLConfig
	DomainRPS       int
	RPZ             []struct{ Path, Action string }
	StatsEnabled    bool
	StatsMaxDomains int
	StatsMaxClients int
	StatsRetention  int
}, m *metrics.Metrics, ctx context.Context) (*BlockingHook, error) {
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

	var stats *filter.BlockingStats
	if cfg.StatsEnabled {
		stats = filter.NewBlockingStats(cfg.StatsMaxDomains, cfg.StatsMaxClients, cfg.StatsRetention)
	}

	h := &BlockingHook{
		priority:      cfg.Priority,
		enabled:       cfg.Enabled,
		filter:        f,
		rpz:           rpzSet,
		action:        action,
		sinkholeIP:    sinkIP,
		domainRPS:     cfg.DomainRPS,
		metrics:       m,
		blocklists:    cfg.Blocklists,
		allowlists:    cfg.Allowlists,
		rpzConfigs:    cfg.RPZ,
		blocklistURLs: cfg.BlocklistURLs,
		stats:         stats,
		statsEnabled:  cfg.StatsEnabled,
	}

	for _, u := range cfg.BlocklistURLs {
		s := filter.NewURLSource(u.URL, u.RefreshInterval, "/tmp/northstar/blocklist-cache")
		h.urlSources = append(h.urlSources, s)
		s.Start(ctx, func() {
			if err := h.ReloadFilter(); err != nil {
				slog.Error("Failed to reload filter after URL source update", "url", u.URL, "error", err)
			}
		})
	}

	return h, nil
}

func (h *BlockingHook) Filter() *filter.Filter                      { return h.filter }
func (h *BlockingHook) RPZ() *filter.RPZSet                         { return h.rpz }
func (h *BlockingHook) Blocklists() []string                        { return h.blocklists }
func (h *BlockingHook) Allowlists() []string                        { return h.allowlists }
func (h *BlockingHook) RPZConfigs() []struct{ Path, Action string } { return h.rpzConfigs }
func (h *BlockingHook) BlockAction() string                         { return h.action }
func (h *BlockingHook) Stats() *filter.BlockingStats                { return h.stats }
func (h *BlockingHook) StatsEnabled() bool                          { return h.statsEnabled }
func (h *BlockingHook) BlocklistURLs() []config.BlocklistURLConfig  { return h.blocklistURLs }

func (h *BlockingHook) ReloadFilter() error {
	paths := make([]string, len(h.blocklists))
	copy(paths, h.blocklists)
	for _, s := range h.urlSources {
		paths = append(paths, s.LocalPath())
	}

	f, err := filter.NewFilter(paths, h.allowlists)
	if err != nil {
		return err
	}
	h.filter = f

	var rpzConfigs []struct{ Path, Action string }
	rpzConfigs = append(rpzConfigs, h.rpzConfigs...)
	if len(rpzConfigs) > 0 {
		rs, err := filter.NewRPZSet(rpzConfigs)
		if err != nil {
			return err
		}
		h.rpz = rs
	}
	return nil
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

	if h.statsEnabled && h.stats != nil {
		h.stats.RecordQuery(ctx.ClientIP)
	}

	action, source := h.checkBlocked(domain, ctx)
	if action == "" {
		return nil
	}

	slog.Warn("Query blocked", "domain", domain, "action", action, "source", source, "client", ctx.ClientIP)

	maxPayload := extractMaxPayload(ctx.Request)

	sendBlockedResponse(ctx.Request, action, h.sinkholeIP, q, maxPayload, ctx.Send)

	h.metrics.BlockedTotal.With(prometheus.Labels{
		"action": action,
		"qtype":  strconv.Itoa(int(q.Type)),
	}).Inc()

	if source != "" {
		h.metrics.BlockedBySourceTotal.With(prometheus.Labels{
			"source": string(source),
			"action": action,
		}).Inc()
	}

	if h.statsEnabled && h.stats != nil {
		h.stats.RecordBlock(domain, ctx.ClientIP)
	}

	return ErrBlocked
}

func (h *BlockingHook) checkBlocked(domain string, ctx *Context) (string, blockSource) {
	if h.filter != nil && h.filter.IsBlocked(domain) {
		return h.action, sourceBlocklist
	}

	if h.rpz != nil {
		if rpzAction, ok := h.rpz.Match(domain); ok {
			return rpzAction, sourceRPZ
		}
	}

	if h.domainRPS > 0 {
		key := "northstar:domainrate:" + domain + ":" + strconv.FormatInt(time.Now().Unix(), 10)
		val, err := ctx.Cache.Incr(ctx.Ctx, key, time.Second)
		if err == nil && val > int64(h.domainRPS) {
			return h.action, sourceDomainRate
		}
	}

	return "", ""
}

func (h *BlockingHook) Close() {
	for _, s := range h.urlSources {
		s.Close()
	}
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func extractMaxPayload(req *dns.Message) uint16 {
	for _, rr := range req.Additionals {
		if rr.Type == dns.TypeOPT {
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
		if sinkholeIP.To4() != nil && q.Type == dns.TypeA {
			rdata = []byte(sinkholeIP.To4())
			rrType = 1
		} else if sinkholeIP.To16() != nil && sinkholeIP.To4() == nil && q.Type == dns.TypeAAAA {
			rdata = []byte(sinkholeIP.To16())
			rrType = 28
		} else if q.Type == dns.TypeAAAA {
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
			Type:  dns.TypeOPT,
			Class: maxPayload,
		}},
	}
	packed := resp.Pack()
	if err := send(packed); err != nil {
		slog.Error("Error writing blocked response", "error", err)
	}
}
