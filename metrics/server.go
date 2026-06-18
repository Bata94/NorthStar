// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

func Serve(ctx context.Context, addr string, m *Metrics) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		slog.Info("Shutting down metrics HTTP server...")
		if err := server.Shutdown(context.Background()); err != nil {
			slog.Error("Metrics HTTP server shutdown error", "error", err)
		}
	}()

	slog.Info("Metrics HTTP server listening", "addr", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics http server: %w", err)
	}
	return nil
}
