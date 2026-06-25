package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/bata94/northstar/cache"
)

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"entries":   s.cache.Len(),
		"evictions": s.cache.Evictions(),
	})
}

func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	entries := s.cache.Len()
	if entries > 0 {
		s.cache = cache.NewMemory(0, nil)
	}
	slog.Info("Cache flushed via API", "entries_removed", entries)
	writeOK(w, map[string]any{"entries_removed": entries})
}

func (s *Server) handleCacheDeleteDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if err := s.cache.DeleteDomain(r.Context(), domain); err != nil {
		writeInternalError(w, "cache delete domain", err)
		return
	}
	writeOK(w, map[string]string{"domain": domain})
}

func (s *Server) handleCacheDelete(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	qtypeStr := r.PathValue("qtype")
	qtype, err := strconv.ParseUint(qtypeStr, 10, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid qtype: "+err.Error())
		return
	}
	if err := s.cache.Delete(r.Context(), domain, uint16(qtype)); err != nil {
		writeInternalError(w, "cache delete", err)
		return
	}
	writeOK(w, map[string]string{"domain": domain, "qtype": qtypeStr})
}

func (s *Server) handleCacheGet(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	qtypeStr := r.PathValue("qtype")
	qtype, err := strconv.ParseUint(qtypeStr, 10, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid qtype: "+err.Error())
		return
	}

	entry, ok := s.cache.Peek(r.Context(), domain, uint16(qtype))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no cache entry for %s/%s", domain, qtypeStr))
		return
	}

	writeOK(w, map[string]any{
		"domain":           entry.Domain,
		"qtype":            entry.QType,
		"rcode":            entry.RCode,
		"authentic_data":   entry.AuthenticData,
		"expires_at":       entry.ExpiresAt.Unix(),
		"ttl_remaining":    int(time.Until(entry.ExpiresAt).Seconds()),
		"hit_count":        entry.HitCount.Load(),
		"answer_count":     len(entry.Answers),
		"authority_count":  len(entry.Authorities),
		"additional_count": len(entry.Additionals),
	})
}
