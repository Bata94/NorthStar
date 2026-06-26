// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package upstream

import (
	"context"
	"crypto/tls"
	"log/slog"
	"math/rand"
	"net"
	"time"

	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
)

type HealthChecker struct {
	upstream *Upstream
	stopCh   chan struct{}
	metrics  *metrics.Metrics
}

func (g *Group) StartHealthChecks(ctx context.Context, m *metrics.Metrics) {
	g.mu.RLock()
	upstreams := make([]*Upstream, len(g.upstreams))
	copy(upstreams, g.upstreams)
	g.mu.RUnlock()

	for _, u := range upstreams {
		if !u.Config.HealthCheck {
			continue
		}
		hc := &HealthChecker{
			upstream: u,
			stopCh:   make(chan struct{}),
			metrics:  m,
		}
		go hc.run(ctx)
	}
}

func (hc *HealthChecker) run(ctx context.Context) {
	interval := time.Duration(hc.upstream.Config.HealthInterval) * time.Second

	timer := time.NewTimer(randInterval(interval))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hc.stopCh:
			return
		case <-timer.C:
			hc.probe()
			timer.Reset(randInterval(interval))
		}
	}
}

func (g *Group) StartSpeedAssessment(ctx context.Context) {
	g.mu.RLock()
	upstreams := make([]*Upstream, len(g.upstreams))
	copy(upstreams, g.upstreams)
	g.mu.RUnlock()

	if len(upstreams) < 2 {
		return
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.reportSpeedRanking()
			}
		}
	}()
}

type speedEntry struct {
	name    string
	latency time.Duration
}

func (g *Group) reportSpeedRanking() {
	g.mu.RLock()
	entries := make([]speedEntry, 0, len(g.upstreams))
	for _, u := range g.upstreams {
		if u.IsHealthy() {
			entries = append(entries, speedEntry{name: u.Name, latency: u.EWMA()})
		}
	}
	g.mu.RUnlock()

	if len(entries) < 2 {
		return
	}

	slog.Info("Upstream speed assessment")
	for _, e := range entries {
		slog.Info("  "+e.name, "latency", e.latency.Round(time.Millisecond).String())
	}
}

func randInterval(base time.Duration) time.Duration {
	jitter := time.Duration(float64(base) * 0.25 * (2*rand.Float64() - 1))
	return base + jitter
}

func (hc *HealthChecker) probe() {
	u := hc.upstream
	probeTO := time.Duration(u.Config.HealthTimeout) * time.Second
	if u.Config.AdaptiveTimeoutFactor > 0 {
		adaptive := u.AdaptiveTimeout()
		if adaptive > probeTO {
			probeTO = adaptive
		}
	}

	start := time.Now()

	if u.DoH != nil {
		hc.probeDoH(probeTO)
		return
	}

	var conn net.Conn
	var err error
	if u.Config.TLS {
		serverName := u.Config.TLSServerName
		if serverName == "" {
			host, _, _ := net.SplitHostPort(u.Config.Address)
			serverName = host
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: probeTO}, "tcp", u.Config.Address, &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = net.DialTimeout("udp", u.Config.Address, probeTO)
	}
	if err != nil {
		slog.Debug("Health probe failed (dial)", "upstream", u.Name, "error", err)
		u.ReportFailure()
		if hc.metrics != nil {
			hc.metrics.UpstreamFails.WithLabelValues(u.Name).Inc()
		}
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Debug("Health probe close error", "upstream", u.Name, "error", err)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(probeTO)); err != nil {
		slog.Debug("Health probe deadline error", "upstream", u.Name, "error", err)
	}

	query := buildProbeQuery()
	if _, err := conn.Write(query); err != nil {
		slog.Debug("Health probe failed (write)", "upstream", u.Name, "error", err)
		u.ReportFailure()
		if hc.metrics != nil {
			hc.metrics.UpstreamFails.WithLabelValues(u.Name).Inc()
		}
		return
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		slog.Debug("Health probe failed (read)", "upstream", u.Name, "error", err)
		u.ReportFailure()
		if hc.metrics != nil {
			hc.metrics.UpstreamFails.WithLabelValues(u.Name).Inc()
		}
		return
	}

	latency := time.Since(start)
	u.RecordLatency(latency)

	if !u.IsHealthy() {
		slog.Info("Upstream recovered", "upstream", u.Name)
	}
	u.ReportSuccess()
	if hc.metrics != nil {
		hc.metrics.UpstreamHealthy.WithLabelValues(u.Name).Set(1)
		hc.metrics.UpstreamProbeDuration.WithLabelValues(u.Name).Observe(latency.Seconds())
	}
}

func (hc *HealthChecker) probeDoH(probeTO time.Duration) {
	u := hc.upstream
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), probeTO)
	defer cancel()

	msg := buildDoHProbeQuery()
	_, err := u.DoH.Query(ctx, msg)
	if err != nil {
		slog.Debug("Health probe failed (DoH)", "upstream", u.Name, "error", err)
		u.ReportFailure()
		if hc.metrics != nil {
			hc.metrics.UpstreamFails.WithLabelValues(u.Name).Inc()
		}
		return
	}

	latency := time.Since(start)
	u.RecordLatency(latency)

	if !u.IsHealthy() {
		slog.Info("Upstream recovered", "upstream", u.Name)
	}
	u.ReportSuccess()
	if hc.metrics != nil {
		hc.metrics.UpstreamHealthy.WithLabelValues(u.Name).Set(1)
		hc.metrics.UpstreamProbeDuration.WithLabelValues(u.Name).Observe(latency.Seconds())
	}
}

func buildDoHProbeQuery() *dns.Message {
	return &dns.Message{
		Header: dns.Header{
			ID:      uint16(time.Now().UnixNano() & 0xFFFF),
			Flags:   0x0100, // standard query
			QDCount: 1,
		},
		Questions: []dns.Question{
			{Name: ".", Type: 1, Class: 1}, // A record for root
		},
	}
}

func buildProbeQuery() []byte {
	id := uint16(time.Now().UnixNano() & 0xFFFF)
	buf := make([]byte, 17)
	buf[0] = byte(id >> 8)
	buf[1] = byte(id)
	buf[2] = 0x01
	buf[3] = 0x00
	buf[4] = 0x00
	buf[5] = 0x01
	buf[6] = 0x00
	buf[7] = 0x00
	buf[8] = 0x00
	buf[9] = 0x00
	buf[10] = 0x00
	buf[11] = 0x00
	buf[12] = 0x00
	buf[13] = 0x00
	buf[14] = 0x01
	buf[15] = 0x00
	buf[16] = 0x01
	return buf
}
