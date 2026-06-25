// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	QueriesTotal              *prometheus.CounterVec
	CacheLookups              prometheus.Counter
	CacheHits                 prometheus.Counter
	UpstreamLatency           *prometheus.HistogramVec
	ErrorsTotal               *prometheus.CounterVec
	ActiveHandlers            prometheus.Gauge
	UpstreamHealthy           *prometheus.GaugeVec
	UpstreamFails             *prometheus.CounterVec
	UpstreamProbeDuration     *prometheus.HistogramVec
	UpstreamQueries           *prometheus.CounterVec
	UpstreamConcurrentWins    *prometheus.CounterVec
	UpstreamConditionalHits   *prometheus.CounterVec
	Registry                  *prometheus.Registry
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

	m.UpstreamConcurrentWins = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "concurrent_wins_total",
		Help:      "Number of concurrent forwarding races won by each upstream.",
	}, []string{"name"})
	reg.MustRegister(m.UpstreamConcurrentWins)

	m.UpstreamConditionalHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "conditional_hits_total",
		Help:      "Conditional route matches per upstream.",
	}, []string{"name", "pattern"})
	reg.MustRegister(m.UpstreamConditionalHits)

	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
