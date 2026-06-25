package zone

import (
	"sort"
	"strings"
)

type Set struct {
	zones []*Zone
}

func NewSet(zones []*Zone) *Set {
	sort.Slice(zones, func(i, j int) bool {
		return len(zones[i].Name) > len(zones[j].Name)
	})
	return &Set{zones: zones}
}

func (s *Set) Lookup(name string) *Zone {
	for _, z := range s.zones {
		if name == z.Name || strings.HasSuffix(name, "."+z.Name) {
			return z
		}
	}
	return nil
}

func (s *Set) Zones() []*Zone {
	return s.zones
}

func (s *Set) Replace(zones []*Zone) {
	sort.Slice(zones, func(i, j int) bool {
		return len(zones[i].Name) > len(zones[j].Name)
	})
	s.zones = zones
}
