package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bata94/northstar/config"
)

type upstreamInput struct {
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	Priority   *int     `json:"priority"`
	Timeout    *int     `json:"timeout"`
	TCPOnly    *bool    `json:"tcp_only"`
	TLS        *bool    `json:"tls"`
	TLSServer  *string  `json:"tls_server_name"`
	DoHURL     *string  `json:"doh_url"`
	DoQ        *bool    `json:"doq"`
	HealthChk  *bool    `json:"health_check"`
	HealthInt  *int     `json:"health_interval"`
	HealthTO   *int     `json:"health_timeout"`
	MaxFails   *int     `json:"max_fails"`
	Weight     *int     `json:"weight"`
	AdaptiveTF *float64 `json:"adaptive_timeout_factor"`
}

func (s *Server) handleUpstreamList(w http.ResponseWriter, r *http.Request) {
	upstreams := s.upstream.Upstreams()
	result := make([]map[string]any, 0, len(upstreams))
	for _, u := range upstreams {
		result = append(result, map[string]any{
			"name":     u.Name,
			"address":  u.Config.Address,
			"priority": u.Config.Priority,
			"healthy":  u.IsHealthy(),
			"latency":  u.EWMA().Milliseconds(),
			"fails":    u.FailCount(),
			"timeout":  u.Config.Timeout,
		})
	}
	writeOK(w, result)
}

func (s *Server) handleUpstreamGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	upstreams := s.upstream.Upstreams()
	for _, u := range upstreams {
		if u.Name == name {
			writeOK(w, map[string]any{
				"name":                    u.Name,
				"address":                 u.Config.Address,
				"priority":                u.Config.Priority,
				"timeout":                 u.Config.Timeout,
				"tcp_only":                u.Config.TCPOnly,
				"tls":                     u.Config.TLS,
				"tls_server_name":         u.Config.TLSServerName,
				"doh_url":                 u.Config.DoHURL,
				"doq":                     u.Config.DoQ,
				"health_check":            u.Config.HealthCheck,
				"health_interval":         u.Config.HealthInterval,
				"health_timeout":          u.Config.HealthTimeout,
				"max_fails":               u.Config.MaxFails,
				"weight":                  u.Config.Weight,
				"adaptive_timeout_factor": u.Config.AdaptiveTimeoutFactor,
				"healthy":                 u.IsHealthy(),
				"latency_ms":              u.EWMA().Milliseconds(),
				"fail_count":              u.FailCount(),
			})
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("upstream %q not found", name))
}

func (s *Server) handleUpstreamCreate(w http.ResponseWriter, r *http.Request) {
	var input upstreamInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if input.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.Address == "" {
		writeError(w, http.StatusBadRequest, "address is required")
		return
	}

	for _, u := range s.cfg.Upstreams {
		if u.Name == input.Name {
			writeError(w, http.StatusConflict, fmt.Sprintf("upstream %q already exists", input.Name))
			return
		}
	}

	uc := config.UpstreamConfig{
		Name:    input.Name,
		Address: input.Address,
	}
	if input.Priority != nil {
		uc.Priority = *input.Priority
	}
	if input.Timeout != nil {
		uc.Timeout = *input.Timeout
	}
	if input.TCPOnly != nil {
		uc.TCPOnly = *input.TCPOnly
	}
	if input.TLS != nil {
		uc.TLS = *input.TLS
	}
	if input.TLSServer != nil {
		uc.TLSServerName = *input.TLSServer
	}
	if input.DoHURL != nil {
		uc.DoHURL = *input.DoHURL
	}
	if input.DoQ != nil {
		uc.DoQ = *input.DoQ
	}
	if input.HealthChk != nil {
		uc.HealthCheck = *input.HealthChk
	}
	if input.HealthInt != nil {
		uc.HealthInterval = *input.HealthInt
	}
	if input.HealthTO != nil {
		uc.HealthTimeout = *input.HealthTO
	}
	if input.MaxFails != nil {
		uc.MaxFails = *input.MaxFails
	}
	if input.Weight != nil {
		uc.Weight = *input.Weight
	}
	if input.AdaptiveTF != nil {
		uc.AdaptiveTimeoutFactor = *input.AdaptiveTF
	}

	s.cfg.Upstreams = append(s.cfg.Upstreams, uc)
	if err := s.persistConfig(); err != nil {
		writeInternalError(w, "failed to persist config", err)
		return
	}
	if err := s.upstream.ReloadConfig(s.cfg); err != nil {
		writeInternalError(w, "failed to reload upstreams", err)
		return
	}
	writeOK(w, map[string]string{"name": input.Name})
}

func (s *Server) handleUpstreamUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var input upstreamInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	idx := -1
	for i, u := range s.cfg.Upstreams {
		if u.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeError(w, http.StatusNotFound, fmt.Sprintf("upstream %q not found", name))
		return
	}

	uc := &s.cfg.Upstreams[idx]
	if input.Name != "" {
		uc.Name = input.Name
	}
	if input.Address != "" {
		uc.Address = input.Address
	}
	if input.Priority != nil {
		uc.Priority = *input.Priority
	}
	if input.Timeout != nil {
		uc.Timeout = *input.Timeout
	}
	if input.TCPOnly != nil {
		uc.TCPOnly = *input.TCPOnly
	}
	if input.TLS != nil {
		uc.TLS = *input.TLS
	}
	if input.TLSServer != nil {
		uc.TLSServerName = *input.TLSServer
	}
	if input.DoHURL != nil {
		uc.DoHURL = *input.DoHURL
	}
	if input.DoQ != nil {
		uc.DoQ = *input.DoQ
	}
	if input.HealthChk != nil {
		uc.HealthCheck = *input.HealthChk
	}
	if input.HealthInt != nil {
		uc.HealthInterval = *input.HealthInt
	}
	if input.HealthTO != nil {
		uc.HealthTimeout = *input.HealthTO
	}
	if input.MaxFails != nil {
		uc.MaxFails = *input.MaxFails
	}
	if input.Weight != nil {
		uc.Weight = *input.Weight
	}
	if input.AdaptiveTF != nil {
		uc.AdaptiveTimeoutFactor = *input.AdaptiveTF
	}

	if err := s.persistConfig(); err != nil {
		writeInternalError(w, "failed to persist config", err)
		return
	}
	if err := s.upstream.ReloadConfig(s.cfg); err != nil {
		writeInternalError(w, "failed to reload upstreams", err)
		return
	}
	writeOK(w, map[string]string{"name": uc.Name})
}

func (s *Server) handleUpstreamDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	idx := -1
	for i, u := range s.cfg.Upstreams {
		if u.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeError(w, http.StatusNotFound, fmt.Sprintf("upstream %q not found", name))
		return
	}

	s.cfg.Upstreams = append(s.cfg.Upstreams[:idx], s.cfg.Upstreams[idx+1:]...)
	if err := s.persistConfig(); err != nil {
		writeInternalError(w, "failed to persist config", err)
		return
	}
	if err := s.upstream.ReloadConfig(s.cfg); err != nil {
		writeInternalError(w, "failed to reload upstreams", err)
		return
	}
	writeOK(w, map[string]string{"deleted": name})
}

func (s *Server) persistConfig() error {
	path := s.cfgPath
	if path == "" {
		path = "./northstar.yaml"
	}
	return config.WriteEffectiveConfig(path, s.cfg)
}
