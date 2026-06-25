package api

import (
	"encoding/json"
	"net/http"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/zone"
)

func (s *Server) handleZoneList(w http.ResponseWriter, r *http.Request) {
	zones := s.authHook.ZoneSet().Zones()
	type zoneInfo struct {
		Name    string `json:"name"`
		Records int    `json:"records"`
	}
	info := make([]zoneInfo, 0, len(zones))
	for _, z := range zones {
		info = append(info, zoneInfo{Name: z.Name, Records: len(z.Records)})
	}
	writeOK(w, info)
}

func (s *Server) handleZoneGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "zone name required")
		return
	}
	if name[len(name)-1] != '.' {
		name += "."
	}

	z := s.authHook.ZoneSet().Lookup(name)
	if z == nil {
		writeError(w, http.StatusNotFound, "zone not found")
		return
	}

	zc := zone.ZoneConfigFromZone(z)
	writeOK(w, zc)
}

func (s *Server) handleZoneCreate(w http.ResponseWriter, r *http.Request) {
	var zc config.ZoneConfig
	if err := decodeJSON(r, &zc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid zone config: "+err.Error())
		return
	}

	z, err := zone.ParseZoneConfig(zc)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid zone: "+err.Error())
		return
	}

	existing := s.authHook.ZoneSet().Lookup(z.Name)
	if existing != nil {
		writeError(w, http.StatusConflict, "zone already exists")
		return
	}

	currentZones := s.authHook.ZoneSet().Zones()
	s.cfg.Zones = append(s.cfg.Zones, zc)
	if err := config.WriteEffectiveConfig(s.cfgPath, s.cfg); err != nil {
		writeInternalError(w, "Failed to persist zone config", err)
		return
	}

	s.authHook.ReplaceZones(append(currentZones, z))
	writeOK(w, map[string]string{"name": z.Name})
}

func (s *Server) handleZoneUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "zone name required")
		return
	}
	if name[len(name)-1] != '.' {
		name += "."
	}

	var zc config.ZoneConfig
	if err := decodeJSON(r, &zc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid zone config: "+err.Error())
		return
	}

	z, err := zone.ParseZoneConfig(zc)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid zone: "+err.Error())
		return
	}

	existing := s.authHook.ZoneSet().Lookup(name)
	if existing == nil {
		writeError(w, http.StatusNotFound, "zone not found")
		return
	}

	// Replace in config and runtime
	currentZones := s.authHook.ZoneSet().Zones()
	for i, zc2 := range s.cfg.Zones {
		zname := zc2.Name
		if zname[len(zname)-1] != '.' {
			zname += "."
		}
		if zname == name {
			s.cfg.Zones[i] = zc
			break
		}
	}
	if err := config.WriteEffectiveConfig(s.cfgPath, s.cfg); err != nil {
		writeInternalError(w, "Failed to persist zone config", err)
		return
	}

	newZones := make([]*zone.Zone, 0, len(currentZones))
	for _, cz := range currentZones {
		if cz.Name == name {
			newZones = append(newZones, z)
		} else {
			newZones = append(newZones, cz)
		}
	}
	s.authHook.ReplaceZones(newZones)
	writeOK(w, map[string]string{"name": z.Name})
}

func (s *Server) handleZoneDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "zone name required")
		return
	}
	if name[len(name)-1] != '.' {
		name += "."
	}

	existing := s.authHook.ZoneSet().Lookup(name)
	if existing == nil {
		writeError(w, http.StatusNotFound, "zone not found")
		return
	}

	// Remove from config
	for i, zc := range s.cfg.Zones {
		zname := zc.Name
		if zname[len(zname)-1] != '.' {
			zname += "."
		}
		if zname == name {
			s.cfg.Zones = append(s.cfg.Zones[:i], s.cfg.Zones[i+1:]...)
			break
		}
	}
	if err := config.WriteEffectiveConfig(s.cfgPath, s.cfg); err != nil {
		writeInternalError(w, "Failed to persist zone config", err)
		return
	}

	currentZones := s.authHook.ZoneSet().Zones()
	newZones := make([]*zone.Zone, 0, len(currentZones))
	for _, cz := range currentZones {
		if cz.Name != name {
			newZones = append(newZones, cz)
		}
	}
	s.authHook.ReplaceZones(newZones)
	writeOK(w, map[string]string{"deleted": name})
}

func (s *Server) handleZoneReload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "zone name required")
		return
	}
	if name[len(name)-1] != '.' {
		name += "."
	}

	// Re-parse from config
	for _, zc := range s.cfg.Zones {
		zname := zc.Name
		if zname[len(zname)-1] != '.' {
			zname += "."
		}
		if zname == name {
			z, err := zone.ParseZoneConfig(zc)
			if err != nil {
				writeInternalError(w, "Failed to re-parse zone", err)
				return
			}
			currentZones := s.authHook.ZoneSet().Zones()
			newZones := make([]*zone.Zone, 0, len(currentZones))
			for _, cz := range currentZones {
				if cz.Name == name {
					newZones = append(newZones, z)
				} else {
					newZones = append(newZones, cz)
				}
			}
			s.authHook.ReplaceZones(newZones)
			writeOK(w, map[string]string{"reloaded": name})
			return
		}
	}
	writeError(w, http.StatusNotFound, "zone not found in config")
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
