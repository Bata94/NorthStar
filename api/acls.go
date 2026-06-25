package api

import (
	"encoding/json"
	"net/http"

	"github.com/bata94/northstar/acl"
	"github.com/bata94/northstar/config"
)

func (s *Server) handleACLList(w http.ResponseWriter, r *http.Request) {
	rules := s.aclHook.ACLSet().Rules()
	type aclInfo struct {
		Name     string `json:"name"`
		Action   string `json:"action"`
		Subnet   string `json:"subnet,omitempty"`
		Zone     string `json:"zone,omitempty"`
		Protocol string `json:"protocol,omitempty"`
		Upstream string `json:"upstream,omitempty"`
	}
	info := make([]aclInfo, 0, len(rules))
	for _, rule := range rules {
		ai := aclInfo{
			Name:   rule.Name,
			Action: rule.Action,
		}
		if rule.Subnet != nil {
			ai.Subnet = rule.Subnet.String()
		}
		if rule.Zone != "" {
			ai.Zone = rule.Zone
		}
		if rule.Protocol != "" {
			ai.Protocol = rule.Protocol
		}
		if rule.Upstream != "" {
			ai.Upstream = rule.Upstream
		}
		info = append(info, ai)
	}
	writeOK(w, info)
}

func (s *Server) handleACLGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "acl name required")
		return
	}

	for _, rule := range s.aclHook.ACLSet().Rules() {
		if rule.Name == name {
			writeOK(w, rule)
			return
		}
	}
	writeError(w, http.StatusNotFound, "acl not found")
}

func (s *Server) handleACLCreate(w http.ResponseWriter, r *http.Request) {
	var ac config.ACLConfig
	if err := json.NewDecoder(r.Body).Decode(&ac); err != nil {
		writeError(w, http.StatusBadRequest, "invalid acl config: "+err.Error())
		return
	}

	// Validate
	s.cfg.ACLs = append(s.cfg.ACLs, ac)
	if err := config.WriteEffectiveConfig(s.cfgPath, s.cfg); err != nil {
		writeInternalError(w, "Failed to persist acl config", err)
		return
	}

	rs, err := acl.NewRuleSet(s.cfg.ACLs)
	if err != nil {
		writeInternalError(w, "Failed to create acl ruleset", err)
		return
	}
	s.aclHook.ReplaceRules(rs)
	writeOK(w, map[string]string{"name": ac.Name})
}

func (s *Server) handleACLUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "acl name required")
		return
	}

	var ac config.ACLConfig
	if err := json.NewDecoder(r.Body).Decode(&ac); err != nil {
		writeError(w, http.StatusBadRequest, "invalid acl config: "+err.Error())
		return
	}

	found := false
	for i, existing := range s.cfg.ACLs {
		if existing.Name == name {
			s.cfg.ACLs[i] = ac
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "acl not found")
		return
	}

	if err := config.WriteEffectiveConfig(s.cfgPath, s.cfg); err != nil {
		writeInternalError(w, "Failed to persist acl config", err)
		return
	}

	rs, err := acl.NewRuleSet(s.cfg.ACLs)
	if err != nil {
		writeInternalError(w, "Failed to create acl ruleset", err)
		return
	}
	s.aclHook.ReplaceRules(rs)
	writeOK(w, map[string]string{"name": ac.Name})
}

func (s *Server) handleACLDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "acl name required")
		return
	}

	found := false
	for i, existing := range s.cfg.ACLs {
		if existing.Name == name {
			s.cfg.ACLs = append(s.cfg.ACLs[:i], s.cfg.ACLs[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "acl not found")
		return
	}

	if err := config.WriteEffectiveConfig(s.cfgPath, s.cfg); err != nil {
		writeInternalError(w, "Failed to persist acl config", err)
		return
	}

	rs, err := acl.NewRuleSet(s.cfg.ACLs)
	if err != nil {
		writeInternalError(w, "Failed to create acl ruleset", err)
		return
	}
	s.aclHook.ReplaceRules(rs)
	writeOK(w, map[string]string{"deleted": name})
}
