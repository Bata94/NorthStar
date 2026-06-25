package api

import (
	"net/http"
	"runtime"
	"time"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	upstreams := s.upstream.Upstreams()
	total := len(upstreams)
	healthy := 0
	for _, u := range upstreams {
		if u.IsHealthy() {
			healthy++
		}
	}
	status := "ok"
	if healthy == 0 && total > 0 {
		status = "degraded"
		writeJSON(w, http.StatusServiceUnavailable, envelope{
			OK:    false,
			Error: "no healthy upstreams",
			Data: map[string]any{
				"status":       status,
				"upstreams":    total,
				"upstreams_ok": healthy,
				"uptime_sec":   int(time.Since(s.started).Seconds()),
				"version":      "dev",
			},
		})
		return
	}
	writeOK(w, map[string]any{
		"status":       status,
		"upstreams":    total,
		"upstreams_ok": healthy,
		"uptime_sec":   int(time.Since(s.started).Seconds()),
		"version":      "dev",
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	upstreams := s.upstream.Upstreams()
	upList := make([]map[string]any, 0, len(upstreams))
	for _, u := range upstreams {
		upList = append(upList, map[string]any{
			"name":     u.Name,
			"address":  u.Config.Address,
			"healthy":  u.IsHealthy(),
			"latency":  u.EWMA().Milliseconds(),
			"fails":    u.FailCount(),
			"priority": u.Config.Priority,
			"timeout":  u.Config.Timeout,
		})
	}

	writeOK(w, map[string]any{
		"uptime_sec":      int(time.Since(s.started).Seconds()),
		"goroutines":      runtime.NumGoroutine(),
		"alloc_mb":        m.Alloc / 1024 / 1024,
		"total_alloc_mb":  m.TotalAlloc / 1024 / 1024,
		"num_gc":          m.NumGC,
		"upstreams":       upList,
		"cache_entries":   s.cache.Len(),
		"cache_evictions": s.cache.Evictions(),
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := *s.cfg
	if cfg.APIKey != "" {
		cfg.APIKey = "***"
	}
	writeOK(w, cfg)
}
