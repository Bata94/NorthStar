// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	QueriesTotal            *prometheus.CounterVec
	CacheLookups            prometheus.Counter
	CacheHits               prometheus.Counter
	CacheEvictionsTotal     *prometheus.CounterVec
	PrefetchesTotal         prometheus.Counter
	NegativeCacheLookups    prometheus.Counter
	NegativeCacheHits       prometheus.Counter
	UpstreamLatency         *prometheus.HistogramVec
	ErrorsTotal             *prometheus.CounterVec
	ActiveHandlers          prometheus.Gauge
	UpstreamHealthy         *prometheus.GaugeVec
	UpstreamFails           *prometheus.CounterVec
	UpstreamProbeDuration   *prometheus.HistogramVec
	UpstreamQueries         *prometheus.CounterVec
	UpstreamConditionalHits *prometheus.CounterVec
	BlockedTotal            *prometheus.CounterVec
	BlockedBySourceTotal    *prometheus.CounterVec
	AllowlistHitsTotal      prometheus.Counter
	DnssecValidationStatus  *prometheus.CounterVec
	Dns64SynthesesTotal     prometheus.Counter
	EcsQueriesTotal         *prometheus.CounterVec
	ZoneQueriesTotal        *prometheus.CounterVec
	Registry                *prometheus.Registry
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{Registry: reg}

	m.QueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "dns",
		Name:      "queries_total",
		Help:      "Total DNS queries received by type (qtype).",
	}, []string{"qtype"})
	reg.MustRegister(m.QueriesTotal)

	m.CacheLookups = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "cache",
		Name:      "lookups_total",
		Help:      "Total cache lookups.",
	})
	reg.MustRegister(m.CacheLookups)

	m.CacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "cache",
		Name:      "hits_total",
		Help:      "Total cache hits (fresh entries).",
	})
	reg.MustRegister(m.CacheHits)

	m.CacheEvictionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "cache",
		Name:      "evictions_total",
		Help:      "Total cache evictions by backend type.",
	}, []string{"backend"})
	reg.MustRegister(m.CacheEvictionsTotal)

	m.PrefetchesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "cache",
		Name:      "prefetches_total",
		Help:      "Total cache entries proactively refreshed before expiry.",
	})
	reg.MustRegister(m.PrefetchesTotal)

	m.NegativeCacheLookups = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "cache",
		Name:      "negative_lookups_total",
		Help:      "Total negative cache lookups.",
	})
	reg.MustRegister(m.NegativeCacheLookups)

	m.NegativeCacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "cache",
		Name:      "negative_hits_total",
		Help:      "Total negative cache hits (NXDOMAIN/NODATA).",
	})
	reg.MustRegister(m.NegativeCacheHits)

	m.UpstreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "latency_seconds",
		Help:      "Latency of upstream DNS queries.",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	}, []string{"name"})
	reg.MustRegister(m.UpstreamLatency)

	m.ErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "dns",
		Name:      "errors_total",
		Help:      "Total DNS errors by type.",
	}, []string{"type"})
	reg.MustRegister(m.ErrorsTotal)

	m.ActiveHandlers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "northstar",
		Subsystem: "dns",
		Name:      "active_handlers",
		Help:      "Number of currently active request handlers.",
	})
	reg.MustRegister(m.ActiveHandlers)

	m.UpstreamHealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "healthy",
		Help:      "Current health status of upstreams (1=healthy, 0=unhealthy).",
	}, []string{"name"})
	reg.MustRegister(m.UpstreamHealthy)

	m.UpstreamFails = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "fails_total",
		Help:      "Total failures per upstream.",
	}, []string{"name"})
	reg.MustRegister(m.UpstreamFails)

	m.UpstreamProbeDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "probe_duration_seconds",
		Help:      "Duration of health check probes.",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	}, []string{"name"})
	reg.MustRegister(m.UpstreamProbeDuration)

	m.UpstreamQueries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "queries_total",
		Help:      "Total queries sent per upstream.",
	}, []string{"name"})
	reg.MustRegister(m.UpstreamQueries)

	m.UpstreamConditionalHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "conditional_hits_total",
		Help:      "Conditional route matches per upstream.",
	}, []string{"name", "pattern"})
	reg.MustRegister(m.UpstreamConditionalHits)

	m.BlockedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "filter",
		Name:      "blocked_total",
		Help:      "Total queries blocked by action and qtype.",
	}, []string{"action", "qtype"})
	reg.MustRegister(m.BlockedTotal)

	m.BlockedBySourceTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "filter",
		Name:      "blocked_by_source_total",
		Help:      "Total queries blocked by blocking source (blocklist, rpz, domain_rate) and action.",
	}, []string{"source", "action"})
	reg.MustRegister(m.BlockedBySourceTotal)

	m.AllowlistHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "filter",
		Name:      "allowlist_hits_total",
		Help:      "Total allowlist matches (domains explicitly allowed).",
	})
	reg.MustRegister(m.AllowlistHitsTotal)

	m.DnssecValidationStatus = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "dnssec",
		Name:      "validation_status_total",
		Help:      "DNSSEC validation results by status (success, failure, skipped).",
	}, []string{"status"})
	reg.MustRegister(m.DnssecValidationStatus)

	m.Dns64SynthesesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "dns64",
		Name:      "syntheses_total",
		Help:      "Total AAAA records synthesized from A records.",
	})
	reg.MustRegister(m.Dns64SynthesesTotal)

	m.EcsQueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "ecs",
		Name:      "queries_total",
		Help:      "Total queries with ECS option injected, by address family.",
	}, []string{"family"})
	reg.MustRegister(m.EcsQueriesTotal)

	m.ZoneQueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "zone",
		Name:      "queries_total",
		Help:      "Total queries answered from authoritative zones.",
	}, []string{"zone", "qtype"})
	reg.MustRegister(m.ZoneQueriesTotal)

	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
