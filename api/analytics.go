package api

import (
	"net/http"
	"strconv"
)

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil || !s.blocking.StatsEnabled() {
		writeError(w, http.StatusBadRequest, "blocking analytics not enabled")
		return
	}

	topN := 10
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			topN = n
		}
	}

	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			days = d
		}
	}

	summary := s.blocking.Stats().Summary(topN)
	if days > 0 && days < len(summary.DailyTrend) {
		summary.DailyTrend = summary.DailyTrend[:days]
		summary.TrendDays = days
	}

	writeOK(w, summary)
}

func (s *Server) handleAnalyticsBlockedDomains(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil || !s.blocking.StatsEnabled() {
		writeError(w, http.StatusBadRequest, "blocking analytics not enabled")
		return
	}

	topN := 20
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			topN = n
		}
	}

	writeOK(w, s.blocking.Stats().TopBlockedDomains(topN))
}

func (s *Server) handleAnalyticsBlockedClients(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil || !s.blocking.StatsEnabled() {
		writeError(w, http.StatusBadRequest, "blocking analytics not enabled")
		return
	}

	topN := 20
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			topN = n
		}
	}

	writeOK(w, s.blocking.Stats().TopBlockedClients(topN))
}

func (s *Server) handleAnalyticsDailyTrend(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil || !s.blocking.StatsEnabled() {
		writeError(w, http.StatusBadRequest, "blocking analytics not enabled")
		return
	}

	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			days = d
		}
	}

	writeOK(w, s.blocking.Stats().DailyTrend(days))
}

func (s *Server) handleAnalyticsReset(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil || !s.blocking.StatsEnabled() {
		writeError(w, http.StatusBadRequest, "blocking analytics not enabled")
		return
	}

	s.blocking.Stats().Reset()
	writeOK(w, map[string]string{"status": "reset"})
}
