package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/hooks"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/upstream"
)

type Server struct {
	cfg      *config.Config
	cfgPath  string
	upstream *upstream.Group
	cache    cache.Cache
	metrics  *metrics.Metrics
	blocking *hooks.BlockingHook
	authHook *hooks.AuthoritativeHook
	aclHook  *hooks.AclHook
	http     *http.Server
	started  time.Time
}

func New(cfg *config.Config, cfgPath string, up *upstream.Group, c cache.Cache, m *metrics.Metrics, bh *hooks.BlockingHook, ah *hooks.AuthoritativeHook, ach *hooks.AclHook) *Server {
	return &Server{
		cfg:      cfg,
		cfgPath:  cfgPath,
		upstream: up,
		cache:    c,
		metrics:  m,
		blocking: bh,
		authHook: ah,
		aclHook:  ach,
		started:  time.Now(),
	}
}

type envelope struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, envelope{OK: true, Data: data})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, envelope{OK: false, Error: msg})
}

func writeInternalError(w http.ResponseWriter, logMsg string, err error) {
	slog.Error(logMsg, "error", err)
	writeError(w, http.StatusInternalServerError, err.Error())
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIKey != "" {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				key = r.URL.Query().Get("api_key")
			}
			if key != s.cfg.APIKey {
				writeError(w, http.StatusUnauthorized, "invalid or missing API key")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) Serve(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	mux.HandleFunc("GET /api/v1/status", s.auth(s.handleStatus))
	mux.HandleFunc("GET /api/v1/config", s.auth(s.handleConfig))

	mux.HandleFunc("GET /api/v1/upstreams", s.auth(s.handleUpstreamList))
	mux.HandleFunc("GET /api/v1/upstreams/{name}", s.auth(s.handleUpstreamGet))
	mux.HandleFunc("POST /api/v1/upstreams", s.auth(s.handleUpstreamCreate))
	mux.HandleFunc("PUT /api/v1/upstreams/{name}", s.auth(s.handleUpstreamUpdate))
	mux.HandleFunc("DELETE /api/v1/upstreams/{name}", s.auth(s.handleUpstreamDelete))

	mux.HandleFunc("GET /api/v1/cache", s.auth(s.handleCacheStats))
	mux.HandleFunc("DELETE /api/v1/cache", s.auth(s.handleCacheFlush))
	mux.HandleFunc("DELETE /api/v1/cache/{domain}", s.auth(s.handleCacheDeleteDomain))
	mux.HandleFunc("DELETE /api/v1/cache/{domain}/{qtype}", s.auth(s.handleCacheDelete))
	mux.HandleFunc("GET /api/v1/cache/{domain}/{qtype}", s.auth(s.handleCacheGet))

	mux.HandleFunc("GET /api/v1/filter/blocklists", s.auth(s.handleBlocklists))
	mux.HandleFunc("GET /api/v1/filter/allowlists", s.auth(s.handleAllowlists))
	mux.HandleFunc("POST /api/v1/filter/reload", s.auth(s.handleFilterReload))
	mux.HandleFunc("POST /api/v1/filter/test", s.auth(s.handleFilterTest))
	mux.HandleFunc("GET /api/v1/filter/stats", s.auth(s.handleFilterStats))

	mux.HandleFunc("GET /api/v1/zones", s.auth(s.handleZoneList))
	mux.HandleFunc("GET /api/v1/zones/{name}", s.auth(s.handleZoneGet))
	mux.HandleFunc("POST /api/v1/zones", s.auth(s.handleZoneCreate))
	mux.HandleFunc("PUT /api/v1/zones/{name}", s.auth(s.handleZoneUpdate))
	mux.HandleFunc("DELETE /api/v1/zones/{name}", s.auth(s.handleZoneDelete))
	mux.HandleFunc("POST /api/v1/zones/{name}/reload", s.auth(s.handleZoneReload))

	mux.HandleFunc("GET /api/v1/acls", s.auth(s.handleACLList))
	mux.HandleFunc("GET /api/v1/acls/{name}", s.auth(s.handleACLGet))
	mux.HandleFunc("POST /api/v1/acls", s.auth(s.handleACLCreate))
	mux.HandleFunc("PUT /api/v1/acls/{name}", s.auth(s.handleACLUpdate))
	mux.HandleFunc("DELETE /api/v1/acls/{name}", s.auth(s.handleACLDelete))

	addr := fmt.Sprintf(":%d", s.cfg.APIPort)
	s.http = &http.Server{Addr: addr, Handler: mux}

	go func() {
		<-ctx.Done()
		slog.Warn("Shutting down API HTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			slog.Error("API HTTP server shutdown error", "error", err)
		}
	}()

	slog.Warn("API HTTP server listening", "addr", addr)
	if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("api http server: %w", err)
	}
	return nil
}
