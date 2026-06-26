package api

import (
	"net/http"
	"strconv"

	"github.com/bata94/northstar/filter"
)

func (s *Server) handleClientList(w http.ResponseWriter, r *http.Request) {
	if s.clientStats == nil {
		writeError(w, http.StatusBadRequest, "client stats not available")
		return
	}

	clients := s.clientStats.GetAllClients()
	writeOK(w, clients)
}

func (s *Server) handleClientGet(w http.ResponseWriter, r *http.Request) {
	if s.clientStats == nil {
		writeError(w, http.StatusBadRequest, "client stats not available")
		return
	}

	ip := r.PathValue("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "missing client IP")
		return
	}

	stat := s.clientStats.GetStats(ip)
	if stat == nil {
		writeError(w, http.StatusNotFound, "client not found")
		return
	}

	writeOK(w, stat)
}

func (s *Server) handleClientTop(w http.ResponseWriter, r *http.Request) {
	if s.clientStats == nil {
		writeError(w, http.StatusBadRequest, "client stats not available")
		return
	}

	n := 10
	if v := r.URL.Query().Get("top"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}

	by := r.URL.Query().Get("by")
	var clients []filter.ClientStat
	switch by {
	case "blocked":
		clients = s.clientStats.TopBlockedClients(n)
	default:
		clients = s.clientStats.TopClients(n)
	}

	writeOK(w, clients)
}

func (s *Server) handleClientReset(w http.ResponseWriter, r *http.Request) {
	if s.clientStats == nil {
		writeError(w, http.StatusBadRequest, "client stats not available")
		return
	}

	s.clientStats.Reset()
	writeOK(w, map[string]string{"status": "reset"})
}
