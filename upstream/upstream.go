// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/pool"
)

type Upstream struct {
	Name    string
	Config  config.UpstreamConfig
	UDPPool *pool.Pool
	TCPPool *pool.Pool
	DoH     *DoHClient
	DoQ     *DoQClient

	healthy     atomic.Bool
	failCount   atomic.Int64
	ewmaLatency atomic.Int64 // nanoseconds
}

const ewmaAlpha = 0.2

func (u *Upstream) IsHealthy() bool {
	return u.healthy.Load()
}

func (u *Upstream) ReportFailure() {
	fails := u.failCount.Add(1)
	if fails >= int64(u.Config.MaxFails) {
		if u.healthy.Load() {
			slog.Warn("Upstream demoted", "upstream", u.Name, "fails", fails, "max_fails", u.Config.MaxFails)
		}
		u.healthy.Store(false)
	}
}

func (u *Upstream) FailCount() int64 {
	return u.failCount.Load()
}

func (u *Upstream) ReportSuccess() {
	wasUnhealthy := !u.healthy.Load()
	u.failCount.Store(0)
	u.healthy.Store(true)
	if wasUnhealthy {
		slog.Info("Upstream promoted", "upstream", u.Name)
	}
}

func (u *Upstream) RecordLatency(d time.Duration) {
	sec := float64(d.Nanoseconds())
	for {
		old := u.ewmaLatency.Load()
		var newVal float64
		if old == 0 {
			newVal = sec
		} else {
			newVal = ewmaAlpha*sec + (1-ewmaAlpha)*float64(old)
		}
		if u.ewmaLatency.CompareAndSwap(old, int64(newVal)) {
			return
		}
	}
}

func (u *Upstream) EWMA() time.Duration {
	return time.Duration(u.ewmaLatency.Load())
}

func (u *Upstream) AdaptiveTimeout() time.Duration {
	staticTO := time.Duration(u.Config.Timeout) * time.Second
	if u.Config.AdaptiveTimeoutFactor <= 0 {
		return staticTO
	}
	adaptive := time.Duration(float64(u.EWMA()) * u.Config.AdaptiveTimeoutFactor)
	if adaptive < staticTO {
		return staticTO
	}
	return adaptive
}

func (u *Upstream) Close() {
	if u.UDPPool != nil {
		u.UDPPool.Close()
	}
	if u.TCPPool != nil {
		u.TCPPool.Close()
	}
	if u.DoH != nil && u.DoH.Origin() != "" && http2Enabled(u.Config) {
		releaseDoHTransport(u.DoH.Origin())
	}
	if u.DoH != nil {
		u.DoH.CloseIdleConnections()
	}
}

func http2Enabled(cfg config.UpstreamConfig) bool {
	if cfg.HTTP2Enabled != nil {
		return *cfg.HTTP2Enabled
	}
	return true // default enabled
}

func newUpstream(cfg config.UpstreamConfig, poolSize, poolIdle int) *Upstream {
	u := &Upstream{
		Name:   cfg.Name,
		Config: cfg,
	}
	idleTO := time.Duration(poolIdle) * time.Second
	if cfg.DoQ {
		u.DoQ = NewDoQClient(cfg.Address, cfg.TLSServerName, cfg.Timeout)
		u.healthy.Store(true)
		return u
	}
	if cfg.DoHURL != "" {
		opts := DoHOptions{
			URL:                 cfg.DoHURL,
			Timeout:             cfg.Timeout,
			ProxyAddress:        cfg.HTTPProxyAddress,
			ProxyAuth:           cfg.HTTPProxyAuth,
			HTTP2Enabled:        http2Enabled(cfg),
			MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		}
		if opts.MaxIdleConnsPerHost < 2 {
			opts.MaxIdleConnsPerHost = 10
		}
		u.DoH = NewDoHClient(opts)
		u.healthy.Store(true)
		return u
	}
	if cfg.TLS {
		serverName := cfg.TLSServerName
		if serverName == "" {
			host, _, err := net.SplitHostPort(cfg.Address)
			if err == nil {
				serverName = host
			} else {
				serverName = cfg.Address
			}
		}
		tc := &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
		tcpPool := pool.New(cfg.Address, "tcp", poolSize, idleTO)
		tcpPool.SetTLSConfig(tc)
		u.TCPPool = tcpPool
		u.UDPPool = pool.New(cfg.Address, "udp", 0, idleTO)
	} else {
		u.UDPPool = pool.New(cfg.Address, "udp", poolSize, idleTO)
		u.TCPPool = pool.New(cfg.Address, "tcp", poolSize, idleTO)
	}
	u.healthy.Store(true)
	return u
}

type conditionalRoute struct {
	pattern  string
	labels   []string
	wildcard bool
	upstream string
}

type Group struct {
	mu          sync.RWMutex
	upstreams   []*Upstream
	byName      map[string]*Upstream
	routes      []conditionalRoute
	Concurrency int
	metrics     *metrics.Metrics
}

func NewGroup(cfg *config.Config, m *metrics.Metrics) (*Group, error) {
	g := &Group{
		byName:      make(map[string]*Upstream),
		Concurrency: cfg.UpstreamConcurrency,
		metrics:     m,
	}

	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}

	names := make(map[string]bool)
	for _, uc := range cfg.Upstreams {
		if uc.Name == "" {
			return nil, fmt.Errorf("upstream name is required")
		}
		if uc.Address == "" {
			return nil, fmt.Errorf("upstream %q: address is required", uc.Name)
		}
		if names[uc.Name] {
			return nil, fmt.Errorf("duplicate upstream name: %q", uc.Name)
		}
		names[uc.Name] = true

		if uc.HealthInterval == 0 {
			uc.HealthInterval = 30
		}
		if uc.HealthTimeout == 0 {
			uc.HealthTimeout = 5
		}
		if uc.MaxFails == 0 {
			uc.MaxFails = 3
		}
		if uc.Timeout == 0 {
			uc.Timeout = 5
		}
		if uc.Weight == 0 {
			uc.Weight = 1
		}
		if uc.HTTP2Enabled == nil {
			enabled := true
			uc.HTTP2Enabled = &enabled
		}
		if uc.MaxIdleConnsPerHost < 2 {
			uc.MaxIdleConnsPerHost = 10
		}

		u := newUpstream(uc, cfg.UpstreamPoolSize, cfg.UpstreamPoolIdle)
		g.upstreams = append(g.upstreams, u)
		g.byName[uc.Name] = u
	}

	for _, rc := range cfg.ConditionalRoutes {
		if rc.Domain == "" {
			return nil, fmt.Errorf("conditional route domain is required")
		}
		if rc.Upstream == "" {
			return nil, fmt.Errorf("conditional route %q: upstream is required", rc.Domain)
		}
		if _, ok := g.byName[rc.Upstream]; !ok {
			return nil, fmt.Errorf("conditional route %q: unknown upstream %q", rc.Domain, rc.Upstream)
		}

		route := conditionalRoute{
			pattern:  rc.Domain,
			upstream: rc.Upstream,
		}
		if strings.HasPrefix(rc.Domain, "*.") {
			route.wildcard = true
			route.labels = splitDomain(rc.Domain[2:])
		} else {
			route.labels = splitDomain(rc.Domain)
		}
		g.routes = append(g.routes, route)
	}

	sort.Slice(g.upstreams, func(i, j int) bool {
		if g.upstreams[i].Config.Priority != g.upstreams[j].Config.Priority {
			return g.upstreams[i].Config.Priority < g.upstreams[j].Config.Priority
		}
		return g.upstreams[i].EWMA() < g.upstreams[j].EWMA()
	})

	return g, nil
}

func splitDomain(domain string) []string {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

func matchDomain(domain string, route conditionalRoute) bool {
	labels := splitDomain(domain)
	if route.wildcard {
		if len(labels) < len(route.labels)+1 {
			return false
		}
		for i := 0; i < len(route.labels); i++ {
			if labels[i] != route.labels[i] {
				return false
			}
		}
		return true
	}
	if len(labels) != len(route.labels) {
		return false
	}
	for i := 0; i < len(labels); i++ {
		if labels[i] != route.labels[i] {
			return false
		}
	}
	return true
}

func (g *Group) SelectN(ctx context.Context, domain string, n int) []*Upstream {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, route := range g.routes {
		if matchDomain(domain, route) {
			if g.metrics != nil {
				g.metrics.UpstreamConditionalHits.WithLabelValues(route.upstream, route.pattern).Inc()
			}
			if u, ok := g.byName[route.upstream]; ok && u.IsHealthy() {
				return []*Upstream{u}
			}
			slog.Warn("Conditional route target unhealthy, falling back",
				"domain", domain, "upstream", route.upstream)
			break
		}
	}

	if n < 1 {
		n = 1
	}
	result := make([]*Upstream, 0, n)
	for _, u := range g.upstreams {
		if u.IsHealthy() {
			result = append(result, u)
			if len(result) >= n {
				break
			}
		}
	}
	return result
}

func (g *Group) Select(ctx context.Context, domain string) (*Upstream, error) {
	upstreams := g.SelectN(ctx, domain, 1)
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("no healthy upstream available")
	}
	return upstreams[0], nil
}

func (g *Group) GetByName(name string) *Upstream {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.byName[name]
}

func (g *Group) Acquire(ctx context.Context, u *Upstream, network string) (net.Conn, error) {
	switch network {
	case "udp":
		return u.UDPPool.Acquire(ctx)
	case "tcp":
		return u.TCPPool.Acquire(ctx)
	default:
		return nil, fmt.Errorf("unknown network: %s", network)
	}
}

func (g *Group) Release(u *Upstream, conn net.Conn, err error) {
	switch {
	case u.Config.TCPOnly:
		u.TCPPool.Release(conn, err)
	case conn.LocalAddr().Network() == "tcp":
		u.TCPPool.Release(conn, err)
	default:
		u.UDPPool.Release(conn, err)
	}
}

func (g *Group) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, u := range g.upstreams {
		u.Close()
	}
}

func (g *Group) Upstreams() []*Upstream {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]*Upstream, len(g.upstreams))
	copy(result, g.upstreams)
	return result
}

func (g *Group) ReloadConfig(cfg *config.Config) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.Concurrency = cfg.UpstreamConcurrency
	newByName := make(map[string]*Upstream)

	for _, uc := range cfg.Upstreams {
		if existing, ok := g.byName[uc.Name]; ok &&
			existing.Config.Address == uc.Address &&
			existing.Config.Timeout == uc.Timeout &&
			existing.Config.TCPOnly == uc.TCPOnly &&
			existing.Config.TLS == uc.TLS &&
			existing.Config.TLSServerName == uc.TLSServerName &&
			existing.Config.DoHURL == uc.DoHURL &&
			existing.Config.DoQ == uc.DoQ &&
			existing.Config.HTTPProxyAddress == uc.HTTPProxyAddress &&
			existing.Config.HTTPProxyAuth == uc.HTTPProxyAuth &&
			existing.Config.HTTP2Enabled == uc.HTTP2Enabled &&
			existing.Config.MaxIdleConnsPerHost == uc.MaxIdleConnsPerHost {
			existing.Config = uc
			newByName[uc.Name] = existing
		} else {
			if existing, ok := g.byName[uc.Name]; ok {
				existing.Close()
			}
			u := newUpstream(uc, cfg.UpstreamPoolSize, cfg.UpstreamPoolIdle)
			newByName[uc.Name] = u
		}
	}

	for _, u := range g.byName {
		if _, keep := newByName[u.Name]; !keep {
			u.Close()
		}
	}

	g.byName = newByName
	g.upstreams = make([]*Upstream, 0, len(newByName))
	for _, u := range newByName {
		g.upstreams = append(g.upstreams, u)
	}

	sort.Slice(g.upstreams, func(i, j int) bool {
		if g.upstreams[i].Config.Priority != g.upstreams[j].Config.Priority {
			return g.upstreams[i].Config.Priority < g.upstreams[j].Config.Priority
		}
		return g.upstreams[i].EWMA() < g.upstreams[j].EWMA()
	})

	var newRoutes []conditionalRoute
	for _, rc := range cfg.ConditionalRoutes {
		route := conditionalRoute{
			pattern:  rc.Domain,
			upstream: rc.Upstream,
		}
		if strings.HasPrefix(rc.Domain, "*.") {
			route.wildcard = true
			route.labels = splitDomain(rc.Domain[2:])
		} else {
			route.labels = splitDomain(rc.Domain)
		}
		newRoutes = append(newRoutes, route)
	}
	g.routes = newRoutes

	return nil
}
