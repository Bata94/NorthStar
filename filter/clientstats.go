package filter

import (
	"cmp"
	"sort"
	"sync"
	"time"
)

type ClientQTypeCount struct {
	QType uint16 `json:"qtype"`
	Count int64  `json:"count"`
}

type ClientDomainStat struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

type ClientStat struct {
	ClientIP     string             `json:"client_ip"`
	TotalQueries int64              `json:"total_queries"`
	BlockedCount int64              `json:"blocked_count"`
	AllowedCount int64              `json:"allowed_count"`
	TopDomains   []ClientDomainStat `json:"top_domains,omitempty"`
	QTypeCount   []ClientQTypeCount `json:"qtype_count,omitempty"`
	BlockRatio   float64            `json:"block_ratio"`
	FirstSeen    time.Time          `json:"first_seen"`
	LastSeen     time.Time          `json:"last_seen"`
}

type clientData struct {
	totalQueries int64
	blockedCount int64
	allowedCount int64
	domains      map[string]int64
	qtypes       map[uint16]int64
	firstSeen    time.Time
	lastSeen     time.Time
}

type ClientStatsCollector struct {
	mu         sync.RWMutex
	clients    map[string]*clientData
	maxClients int
	enabled    bool
}

func NewClientStatsCollector(maxClients int) *ClientStatsCollector {
	if maxClients < 1 {
		maxClients = 1000
	}
	return &ClientStatsCollector{
		clients:    make(map[string]*clientData),
		maxClients: maxClients,
		enabled:    true,
	}
}

func (c *ClientStatsCollector) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

func (c *ClientStatsCollector) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

func (c *ClientStatsCollector) RecordQuery(clientIP, domain string, qtype uint16, blocked bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return
	}

	cd, ok := c.clients[clientIP]
	if !ok {
		if len(c.clients) >= c.maxClients {
			for k := range c.clients {
				delete(c.clients, k)
				break
			}
		}
		cd = &clientData{
			domains:   make(map[string]int64),
			qtypes:    make(map[uint16]int64),
			firstSeen: time.Now(),
		}
		c.clients[clientIP] = cd
	}

	cd.totalQueries++
	if blocked {
		cd.blockedCount++
	} else {
		cd.allowedCount++
	}
	cd.domains[domain]++
	cd.qtypes[qtype]++
	cd.lastSeen = time.Now()
}

func (c *ClientStatsCollector) GetStats(clientIP string) *ClientStat {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cd, ok := c.clients[clientIP]
	if !ok {
		return nil
	}

	return c.buildStat(clientIP, cd)
}

func (c *ClientStatsCollector) GetAllClients() []ClientStat {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]ClientStat, 0, len(c.clients))
	for ip, cd := range c.clients {
		result = append(result, *c.buildStat(ip, cd))
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalQueries > result[j].TotalQueries
	})

	return result
}

func (c *ClientStatsCollector) buildStat(clientIP string, cd *clientData) *ClientStat {
	ratio := 0.0
	if cd.totalQueries > 0 {
		ratio = float64(cd.blockedCount) / float64(cd.totalQueries)
	}

	topDomains := make([]ClientDomainStat, 0, len(cd.domains))
	for domain, count := range cd.domains {
		topDomains = append(topDomains, ClientDomainStat{Domain: domain, Count: count})
	}
	sort.Slice(topDomains, func(i, j int) bool {
		return topDomains[i].Count > topDomains[j].Count
	})
	if len(topDomains) > 10 {
		topDomains = topDomains[:10]
	}

	qtypeCount := make([]ClientQTypeCount, 0, len(cd.qtypes))
	for qtype, count := range cd.qtypes {
		qtypeCount = append(qtypeCount, ClientQTypeCount{QType: qtype, Count: count})
	}
	sort.Slice(qtypeCount, func(i, j int) bool {
		return qtypeCount[i].Count > qtypeCount[j].Count
	})

	return &ClientStat{
		ClientIP:     clientIP,
		TotalQueries: cd.totalQueries,
		BlockedCount: cd.blockedCount,
		AllowedCount: cd.allowedCount,
		TopDomains:   topDomains,
		QTypeCount:   qtypeCount,
		BlockRatio:   ratio,
		FirstSeen:    cd.firstSeen,
		LastSeen:     cd.lastSeen,
	}
}

func (c *ClientStatsCollector) TopClients(n int) []ClientStat {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if n < 1 {
		n = 10
	}

	type pair struct {
		ip  string
		val *clientData
	}
	pairs := make([]pair, 0, len(c.clients))
	for ip, cd := range c.clients {
		pairs = append(pairs, pair{ip, cd})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].val.totalQueries > pairs[j].val.totalQueries
	})

	if n > len(pairs) {
		n = len(pairs)
	}

	result := make([]ClientStat, n)
	for i := 0; i < n; i++ {
		result[i] = *c.buildStat(pairs[i].ip, pairs[i].val)
	}
	return result
}

func (c *ClientStatsCollector) TopBlockedClients(n int) []ClientStat {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if n < 1 {
		n = 10
	}

	type pair struct {
		ip  string
		val *clientData
	}
	pairs := make([]pair, 0, len(c.clients))
	for ip, cd := range c.clients {
		pairs = append(pairs, pair{ip, cd})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].val.blockedCount != pairs[j].val.blockedCount {
			return cmp.Compare(pairs[j].val.blockedCount, pairs[i].val.blockedCount) < 0
		}
		return pairs[i].val.totalQueries > pairs[j].val.totalQueries
	})

	if n > len(pairs) {
		n = len(pairs)
	}

	result := make([]ClientStat, n)
	for i := 0; i < n; i++ {
		result[i] = *c.buildStat(pairs[i].ip, pairs[i].val)
	}
	return result
}

func (c *ClientStatsCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients = make(map[string]*clientData)
}

func (c *ClientStatsCollector) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.clients)
}
