package resolver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/upstream"
)

func ServeDOH(ctx context.Context, addr string, tlscfg *tls.Config, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		handleDOHQuery(ctx, w, r, group, c, runtimeCfg, m)
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    tlscfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	slog.Warn("DoH server listening", "addr", addr)

	errCh := make(chan error, 1)
	go func() {
		if tlscfg != nil {
			errCh <- srv.ListenAndServeTLS("", "")
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func handleDOHQuery(ctx context.Context, w http.ResponseWriter, r *http.Request, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) {
	var body []byte

	switch r.Method {
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); !strings.EqualFold(ct, "application/dns-message") {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		var err error
		body, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "invalid base64url encoding", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if len(body) < 12 {
		http.Error(w, "packet too short", http.StatusBadRequest)
		return
	}

	var req dns.Message
	if err := req.Parse(body); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}

	if len(req.Questions) == 0 {
		http.Error(w, "no questions", http.StatusBadRequest)
		return
	}

	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	maxPayload, do := clientEDNS(&req)

	send := func(resp []byte) error {
		w.Header().Set("Content-Type", "application/dns-message")
		_, err := w.Write(resp)
		return err
	}

	processQuery(ctx, &req, "tcp", clientIP, maxPayload, do, send, group, c, runtimeCfg, m)
}
