package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func (s *Server) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil {
		writeOK(w, []any{})
		return
	}
	paths := s.blocking.Blocklists()
	result := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		count := 0
		if f := s.blocking.Filter(); f != nil {
			count = f.BlocklistLen()
		}
		result = append(result, map[string]any{
			"path":  p,
			"count": count,
		})
	}
	writeOK(w, result)
}

func (s *Server) handleAllowlists(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil {
		writeOK(w, []any{})
		return
	}
	paths := s.blocking.Allowlists()
	result := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		count := 0
		if f := s.blocking.Filter(); f != nil {
			count = f.AllowlistLen()
		}
		result = append(result, map[string]any{
			"path":  p,
			"count": count,
		})
	}
	writeOK(w, result)
}

func (s *Server) handleFilterReload(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil {
		writeError(w, http.StatusBadRequest, "blocking hook not enabled")
		return
	}
	if err := s.blocking.ReloadFilter(); err != nil {
		writeInternalError(w, "filter reload", err)
		return
	}
	slog.Info("Filters reloaded via API")
	writeOK(w, map[string]string{"status": "reloaded"})
}

func (s *Server) handleFilterTest(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if input.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}

	blocked := false
	action := ""
	by := ""

	if s.blocking != nil {
		if s.blocking.Filter() != nil && s.blocking.Filter().IsBlocked(input.Domain) {
			blocked = true
			action = s.blocking.BlockAction()
			by = "blocklist"
		}
		if s.blocking.RPZ() != nil {
			if rpzAction, ok := s.blocking.RPZ().Match(input.Domain); ok {
				blocked = true
				action = rpzAction
				by = "rpz"
			}
		}
	}

	writeOK(w, map[string]any{
		"domain":  input.Domain,
		"blocked": blocked,
		"action":  action,
		"by":      by,
	})
}

func (s *Server) handleFilterStats(w http.ResponseWriter, r *http.Request) {
	blockListCount := 0
	allowListCount := 0
	rpzCount := 0
	if s.blocking != nil {
		if f := s.blocking.Filter(); f != nil {
			blockListCount = f.BlocklistLen()
			allowListCount = f.AllowlistLen()
		}
		if rpz := s.blocking.RPZ(); rpz != nil {
			rpzCount = rpz.Len()
		}
	}

	writeOK(w, map[string]any{
		"blocklist_entries": blockListCount,
		"allowlist_entries": allowListCount,
		"rpz_zones":         rpzCount,
		"blocklists":        s.blocking.Blocklists(),
		"allowlists":        s.blocking.Allowlists(),
	})
}
