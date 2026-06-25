// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
)

func Serve(ctx context.Context, addr string, m *Metrics, debug bool) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())

	if debug {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		slog.Warn("pprof debug endpoints enabled on metrics HTTP server")
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		slog.Warn("Shutting down metrics HTTP server...")
		if err := server.Shutdown(context.Background()); err != nil {
			slog.Error("Metrics HTTP server shutdown error", "error", err)
		}
	}()

	slog.Warn("Metrics HTTP server listening", "addr", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics http server: %w", err)
	}
	return nil
}
