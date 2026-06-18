// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	QueriesTotal    *prometheus.CounterVec
	CacheLookups    prometheus.Counter
	CacheHits       prometheus.Counter
	UpstreamLatency prometheus.Histogram
	ErrorsTotal     *prometheus.CounterVec
	ActiveHandlers  prometheus.Gauge
	Registry        *prometheus.Registry
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

	m.UpstreamLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "northstar",
		Subsystem: "upstream",
		Name:      "latency_seconds",
		Help:      "Latency of upstream DNS queries.",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	})
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

	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
