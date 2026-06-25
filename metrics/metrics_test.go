// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package metrics

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("expected non-nil metrics")
	}
	if m.Registry == nil {
		t.Error("expected non-nil registry")
	}
}

func TestMetricsHandler(t *testing.T) {
	m := New()
	handler := m.Handler()
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	server := &http.Server{Addr: "127.0.0.1:0", Handler: handler}
	defer func() { _ = server.Close() }()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	go func() { _ = server.Serve(l) }()

	resp, err := http.Get("http://" + l.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMetricsServe(t *testing.T) {
	m := New()
	ctx, cancel := context.WithCancel(context.Background())

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(ctx, addr, m, false)
	}()

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for server shutdown")
	}
}

func TestMetricsHandlerServes(t *testing.T) {
	m := New()
	m.QueriesTotal.WithLabelValues("1").Inc()
	m.QueriesTotal.WithLabelValues("28").Inc()
	m.CacheLookups.Inc()
	m.CacheHits.Inc()
	m.UpstreamLatency.WithLabelValues("").Observe(0.05)
	m.ErrorsTotal.WithLabelValues("servfail").Inc()
	m.ActiveHandlers.Inc()
	m.ActiveHandlers.Dec()

	handler := m.Handler()

	server := &http.Server{Addr: "127.0.0.1:0", Handler: handler}
	defer func() { _ = server.Close() }()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	go func() { _ = server.Serve(l) }()

	resp, err := http.Get("http://" + l.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMetricsServeShutdown(t *testing.T) {
	m := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Serve(ctx, "127.0.0.1:0", m, false)
	if err != nil {
		t.Fatal(err)
	}
}
